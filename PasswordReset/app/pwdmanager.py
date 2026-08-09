import re
import hmac
import time
import hashlib
import secrets
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import redis
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from ipalib import api, errors as ipaerrors

from .providers import (
    AmazonSNSFailed,
    AmazonSNSValidateFailed,
    EmailSendFailed,
    EmailValidateFailed,
    SignalFailed,
    SignalValidateFailed,
    SlackValidateFailed,
    SlackSendFailed,
)

logger = logging.getLogger(__name__)

# Subprocess / network timeouts (seconds).
KLIST_TIMEOUT = 5
KINIT_TIMEOUT = 10
REDIS_CONNECT_TIMEOUT = getattr(settings, "REDIS_CONNECT_TIMEOUT", 3)
REDIS_SOCKET_TIMEOUT = getattr(settings, "REDIS_SOCKET_TIMEOUT", 3)
REDIS_MAX_CONNECTIONS = getattr(settings, "REDIS_MAX_CONNECTIONS", 50)
# How long a verified-but-not-yet-completed reset attempt holds exclusive
# claim on an uid (see __acquire_reset_session). Independent of TOKEN_LIFETIME
# - this only needs to outlast one form submission/IPA round trip, not the
# lifetime of the OTP itself.
RESET_SESSION_TTL = 120
# first_phase's outcome (success OR the generic-failure path) is padded to
# take at least this long, wall-clock, regardless of which branch actually
# ran - a nonexistent account failing fast at one LDAP lookup vs a real
# account continuing on through token generation and an SMTP send
# otherwise take measurably different amounts of time, and that
# difference alone is a usable enumeration signal even with identical
# response bodies. This replaces padding just the "not found" path with a
# single guessed constant, which only worked if that guess happened to
# exceed every real success-path duration - a moving target under load.
# Tune this against your own observed p99 send latency in production;
# start conservative and measure rather than guess.
MIN_FIRST_PHASE_DURATION = getattr(settings, "MIN_FIRST_PHASE_DURATION", 1.0)

# HMAC key for hashing OTPs before they're written to Redis (see
# __hash_token). Falls back to Django's SECRET_KEY if no dedicated key is
# configured, so this works out of the box, but a dedicated key is
# recommended for production: it lets you rotate the OTP-hashing key
# independently of SECRET_KEY (which also signs sessions/CSRF tokens, so
# rotating it has broader blast radius than you want just to rotate this).
OTP_HASH_KEY = getattr(settings, "OTP_HASH_KEY", None) or settings.SECRET_KEY

# Never put str(exception) from Redis/IPA into anything that reaches an
# HTTP response - internal error text can contain hostnames, ports, DNs,
# or other backend details we don't want handed to an unauthenticated
# caller. Log the real exception; return this to callers instead.
GENERIC_BACKEND_MESSAGE = "A backend error occurred. Please try again later."

# Atomically increment a counter and, only on the call that creates it,
# set its expiry - single Redis round trip, no INCR-then-EXPIRE race.
_INCR_WITH_TTL_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if tonumber(count) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""

# Shared connection pool, built once when this module is first imported -
# NOT one per PasswdManager() instance. PasswdManager is currently
# instantiated fresh on every request (see views.py); without a shared
# pool, each of those would build its own independent pool of sockets to
# Redis, and under concurrent load that adds up fast toward exhausting
# available file descriptors/ports for no real benefit, since redis-py's
# own pool already handles concurrent reuse safely across threads.
REDIS_POOL = redis.ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True,
    socket_connect_timeout=REDIS_CONNECT_TIMEOUT,
    socket_timeout=REDIS_SOCKET_TIMEOUT,
    max_connections=REDIS_MAX_CONNECTIONS,
)

# Registering a Lua script just wraps the script text with its SHA1 digest
# client-side - it doesn't require a live connection at call time (the
# first real invocation transparently does EVALSHA, falling back to EVAL
# +caching on a NOSCRIPT miss). So this can happen once, at import time,
# bound to a throwaway client on the SAME shared pool above, rather than
# being rebuilt on every PasswdManager() instantiation for no benefit.
_INCR_WITH_TTL_LUA = redis.Redis(connection_pool=REDIS_POOL).register_script(
    _INCR_WITH_TTL_SCRIPT
)


# Custom exceptions
class TooMuchRetries(Exception):
    pass


class ValidateUserFailed(Exception):
    pass


class BackendError(Exception):
    pass


class InvalidToken(Exception):
    pass


class InvalidProvider(Exception):
    pass


class SetPasswordFailed(Exception):
    pass


class KerberosInitFailed(Exception):
    pass


class InvalidIdentifierDomain(Exception):
    """Raised when the submitted identifier looks like an email but uses a
    domain outside ORG_EMAIL_DOMAINS (and not a subdomain of one). This is
    a pure input-format check performed BEFORE any account lookup happens,
    so - unlike almost everything else in this file - it's safe to surface
    directly: it reveals nothing about whether any particular account
    exists, since it fires identically for every rejected domain regardless
    of what's actually in FreeIPA."""


class GenericResetFailure(Exception):
    """Raised for any first_phase failure that must NOT leak details
    (account existence, lock state, missing email, provider errors, etc.)
    to an unauthenticated caller. Always caught at the view layer and
    turned into the same generic message regardless of the cause."""


# Failure modes from user/account resolution or token delivery that are
# "expected" in the sense that they happen during normal operation (bad
# username, locked account, no alt-email, SMTP hiccup, etc). These get a
# WARNING-level, one-line log. Anything NOT in this tuple is treated as a
# genuine bug and gets logger.exception() with a full traceback instead.
_EXPECTED_FIRST_PHASE_ERRORS = (
    ValidateUserFailed,
    BackendError,
    InvalidProvider,
    AmazonSNSFailed,
    AmazonSNSValidateFailed,
    EmailSendFailed,
    SignalFailed,
    SignalValidateFailed,
    SlackValidateFailed,
    SlackSendFailed,
)


class PasswdManager:
    def __init__(self):
        if not self.__kerberos_has_ticket():
            self.__kerberos_init()

        # Always ensure api is bootstrapped with context='cli' so Backend.rpcclient is attached
        if not api.isdone("finalize") or not hasattr(api, "Backend"):
            api.bootstrap_with_global_options(context="cli")
            if not api.isdone("finalize"):
                api.finalize()

        self.__ensure_connected()

        self.redis = redis.Redis(connection_pool=REDIS_POOL)

        # Fail fast and clearly at startup if Redis isn't actually
        # reachable, rather than only discovering it deep inside the
        # first request that happens to touch a token.
        try:
            self.redis.ping()
        except redis.RedisError as e:
            logger.error(f"Redis health check (PING) failed: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

        self._incr_with_ttl_script = _INCR_WITH_TTL_LUA

    # ---------------------------------------------------------------------
    # Kerberos / IPA RPC plumbing
    # ---------------------------------------------------------------------

    @staticmethod
    def __kerberos_has_ticket():
        try:
            process = subprocess.run(
                ["/usr/bin/klist", "-s"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=KLIST_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error(f"klist did not respond within {KLIST_TIMEOUT}s")
            return False
        except OSError as e:
            # Covers FileNotFoundError (binary missing/not installed) and
            # PermissionError (not executable), among others. Treat as "no
            # ticket" - __kerberos_init() below will hit the same problem
            # and raise a properly typed KerberosInitFailed for it.
            logger.error(f"Could not execute klist: {e}")
            return False
        return process.returncode == 0

    @staticmethod
    def __kerberos_init():
        try:
            process = subprocess.run(
                [
                    "/usr/bin/kinit",
                    "-k",
                    "-t",
                    str(settings.KEYTAB_PATH),
                    str(settings.LDAP_USER),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=KINIT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error(f"kinit did not complete within {KINIT_TIMEOUT}s")
            raise KerberosInitFailed("Timed out obtaining Kerberos ticket.")
        except OSError as e:
            logger.error(f"Could not execute kinit: {e}")
            raise KerberosInitFailed("Cannot execute kinit.")

        if process.returncode != 0:
            logger.error("Kerberos ticket initialization failed.")
            raise KerberosInitFailed("Cannot retrieve Kerberos ticket.")

    def __ensure_connected(self):
        """Ensures the FreeIPA RPC client is connected and ready."""
        try:
            if hasattr(api, "Backend") and hasattr(api.Backend, "rpcclient"):
                if not api.Backend.rpcclient.isconnected():
                    api.Backend.rpcclient.connect()
            else:
                # Force re-bootstrap under CLI context if Backend plugins are missing
                api.bootstrap_with_global_options(context="cli")
                if not api.isdone("finalize"):
                    api.finalize()
                api.Backend.rpcclient.connect()
        except Exception as e:
            logger.error(f"Cannot connect to FreeIPA: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

    def __call_ipa(self, command, **kwargs):
        """Run an ipalib Command, transparently recovering once if the RPC
        connection dropped (NetworkError) or the Kerberos credential cache
        expired underneath us (CCacheError). If the retry ALSO fails with
        the same class of transient error, that's converted to a generic
        BackendError rather than letting a raw ipalib exception (which can
        contain internal hostnames/DNs) propagate up to the caller. Any
        other exception type on the retry (NotFound, ValidationError, etc.)
        is a legitimate application-level result, not a connectivity
        failure, and is left to propagate normally so callers can handle it
        the same way they would on a first-attempt success."""
        self.__ensure_connected()
        try:
            return command(**kwargs)
        except ipaerrors.CCacheError as e:
            logger.warning(
                f"Kerberos credential cache expired/invalid ({e}); re-running kinit"
            )
            try:
                api.Backend.rpcclient.disconnect()
            except Exception:
                pass
            self.__kerberos_init()
            self.__ensure_connected()
            try:
                return command(**kwargs)
            except (ipaerrors.CCacheError, ipaerrors.NetworkError):
                logger.exception("FreeIPA still unreachable after Kerberos re-init")
                raise BackendError(GENERIC_BACKEND_MESSAGE)
        except ipaerrors.NetworkError as e:
            logger.warning(f"IPA RPC network error ({e}), attempting one reconnect")
            try:
                api.Backend.rpcclient.disconnect()
            except Exception:
                pass
            self.__ensure_connected()
            try:
                return command(**kwargs)
            except (ipaerrors.CCacheError, ipaerrors.NetworkError):
                logger.exception("FreeIPA still unreachable after reconnect")
                raise BackendError(GENERIC_BACKEND_MESSAGE)

    # ---------------------------------------------------------------------
    # Redis helpers - every real Redis call goes through one of these so
    # connection/timeout errors are handled in exactly one place, are
    # always logged with full detail, and only ever surface externally as
    # a generic BackendError.
    # ---------------------------------------------------------------------

    def __redis_get(self, key):
        try:
            return self.redis.get(key)
        except redis.RedisError as e:
            logger.error(f"Redis GET failed for key={key!r}: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

    def __redis_set(self, key, value, ex=None):
        try:
            self.redis.set(key, value, ex=ex)
        except redis.RedisError as e:
            logger.error(f"Redis SET failed for key={key!r}: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

    def __redis_delete(self, *keys):
        try:
            self.redis.delete(*keys)
        except redis.RedisError as e:
            logger.error(f"Redis DELETE failed for keys={keys!r}: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

    def __redis_incr_with_ttl(self, key, ttl_seconds):
        """Atomic INCR + conditional EXPIRE via a Lua script - Redis
        guarantees the whole script runs as a single, uninterruptible
        operation, so there's no window between the two calls where a
        concurrent request for the same key could observe a count without
        its TTL applied yet."""
        try:
            return self._incr_with_ttl_script(keys=[key], args=[ttl_seconds])
        except redis.RedisError as e:
            logger.error(f"Redis rate-limit script failed for key={key!r}: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

    # ---------------------------------------------------------------------
    # Password policy / password set
    # ---------------------------------------------------------------------

    def __validate_password(self, new_password, uid):
        """Check new_password two ways: (1) Django's AUTH_PASSWORD_VALIDATORS
        chain - CommonPasswordValidator, NumericPasswordValidator,
        UserAttributeSimilarityValidator (activated here via a fake user
        object exposing uid as .username - it silently no-ops without a
        user object), and PwnedPasswordsValidator (HIBP breach check,
        k-anonymity, fails open to CommonPasswordValidator on API errors -
        see settings.py's AUTH_PASSWORD_VALIDATORS for OPTIONS). Then
        (2) FreeIPA's live policy for this specific user (accounts for
        group-priority policies, not just the global one) - this is
        deliberately NOT covered by Django's MinimumLengthValidator, which
        would be a hardcoded floor independent of live IPA policy and
        could silently diverge from it if policy is ever changed."""
        try:
            fake_user = SimpleNamespace(
                username=uid, first_name="", last_name="", email=""
            )
            validate_password(password=new_password, user=fake_user)
        except ValidationError as e:
            raise SetPasswordFailed("; ".join(e.messages))

        try:
            policy = self.__call_ipa(api.Command.pwpolicy_show, user=uid)["result"]
            # Real LDAP/Kerberos attribute names - krbpwdminlength /
            # krbpwdmindiffchars - NOT the ipa CLI flag names (--minlength
            # / --minclasses). Using the CLI names here silently falls
            # through to the hardcoded defaults below every time.
            min_length = int(policy.get("krbpwdminlength", [8])[0])
            required_classes = int(policy.get("krbpwdmindiffchars", [4])[0])
        except BackendError:
            raise
        except Exception:
            logger.exception(
                f"Could not fetch live password policy for uid={uid!r}, using defaults"
            )
            min_length = 8
            required_classes = 4

        def count_character_classes(password):
            classes = 0
            if re.search(r"[a-z]", password):
                classes += 1
            if re.search(r"[A-Z]", password):
                classes += 1
            if re.search(r"\d", password):
                classes += 1
            if re.search(r'[!@#$%^&*()_\-+=\[\]{}|\\:;"\'<>,.?/~`]', password):
                classes += 1
            return classes

        if len(new_password) < min_length:
            raise SetPasswordFailed(
                f"Password must be at least {min_length} characters long."
            )

        if count_character_classes(new_password) < required_classes:
            raise SetPasswordFailed(
                f"Password must include at least {required_classes} character types: "
                "lowercase, uppercase, digits, and special characters."
            )

    def __set_password(self, uid, password):
        try:
            self.__call_ipa(api.Command.user_mod, uid=uid, userpassword=password)

            policy = self.__call_ipa(api.Command.pwpolicy_show, user=uid)["result"]
            exp_days = int(policy.get("krbmaxpwdlife", [0])[0])
            if exp_days > 0:
                expiration = (
                    datetime.now(timezone.utc) + timedelta(days=exp_days)
                ).strftime("%Y%m%d%H%M%SZ")
                self.__call_ipa(
                    api.Command.user_mod,
                    uid=uid,
                    setattr=f"krbPasswordExpiration={expiration}",
                )

            user = self.__get_user(uid)
            failed_count = int(user["result"].get("krbloginfailedcount", ["0"])[0])
            if failed_count > 0:
                self.__call_ipa(
                    api.Command.user_mod, uid=uid, setattr="krbloginfailedcount=0"
                )

        except BackendError:
            raise
        except ipaerrors.DatabaseError as e:
            # Confirmed via direct testing against this exact user_mod call
            # path (authenticated as the service account, not a self-bind):
            # FreeIPA's native passwordHistory constraint raises this
            # specific exception type when the new password matches one
            # already in the account's history (krbpwdhistorylength) -
            # covers ALL historical passwords, not just the immediately
            # previous one. Matching on exception TYPE rather than message
            # text ("Constraint violation: Password reuse not permitted" at
            # test time) since wording could vary by IPA version/locale;
            # the type is what's actually stable across those.
            logger.info(f"Password reuse rejected by IPA for uid={uid!r}: {e}")
            raise SetPasswordFailed(
                "That password can't be used - it matches one you've used recently."
            )
        except ipaerrors.ExecutionError as e:
            error_text = str(e).lower()
            if "password" in error_text and "policy" in error_text:
                raise SetPasswordFailed(f"Password policy violation: {e}")
            logger.exception(
                f"Unexpected IPA ExecutionError setting password for uid={uid!r}"
            )
            raise BackendError(GENERIC_BACKEND_MESSAGE)
        except ipaerrors.ValidationError as e:
            raise SetPasswordFailed(f"Validation failed: {e}")
        except ipaerrors.NotFound:
            raise ValidateUserFailed("User not found")
        except ipaerrors.ACIError:
            raise SetPasswordFailed("Insufficient permissions to set password")
        except Exception:
            logger.exception(f"Unexpected error setting password for uid={uid!r}")
            raise SetPasswordFailed("Unexpected error when setting password.")

    @classmethod
    def __validate_identifier_domain(cls, identifier):
        """If identifier looks like an email (contains '@'), its domain
        MUST be one of ORG_EMAIL_DOMAINS or a subdomain of one - anything
        else is rejected outright, before any IPA lookup happens. Bare
        usernames (no '@') always pass through untouched. This means a
        personal address like jdoe@gmail.com can no longer be used to
        identify an account here at all, even if it happens to be stored
        in someone's alt-email ('street') field - only ucu-family
        email or a bare username is accepted as an identifier."""
        if "@" not in identifier:
            return
        org_domains = getattr(settings, "ORG_EMAIL_DOMAINS", [])
        _, _, domain = identifier.rpartition("@")
        if not cls.__domain_matches_org(domain, org_domains):
            logger.warning(
                f"Rejected identifier domain {domain!r} (from identifier={identifier!r}); "
                f"configured ORG_EMAIL_DOMAINS={org_domains!r}"
            )
            raise InvalidIdentifierDomain(
                "Please enter your username or your UCU email address."
            )

    @staticmethod
    def __domain_matches_org(domain, org_domains):
        """True if domain equals one of org_domains exactly, OR is a
        subdomain of one (e.g. 'staff.ucu.ac.ug' matches org domain
        'ucu.ac.ug'). Deliberately NOT a naive substring/endswith(org_domain)
        check on its own - that would wrongly match something like
        'notucu.ac.ug' against 'ucu.ac.ug'. Requiring either an exact match
        or a match preceded by a literal '.' avoids that false positive."""
        domain = domain.strip().lower()
        for org_domain in org_domains:
            org_domain = org_domain.strip().lower()
            if not org_domain:
                continue
            if domain == org_domain or domain.endswith("." + org_domain):
                return True
        return False

    @classmethod
    def __strip_org_domain(cls, identifier):
        """If identifier looks like <uid>@<org domain or subdomain of it>
        (the institutional convention - e.g. 'jdoe@ucu.ac.ug' or
        'jdoe@staff.ucu.ac.ug'), strip the domain so a direct, exact uid
        lookup can match - username always equals uid here, so this alone
        covers "typed my email instead of my username" cases."""
        org_domains = getattr(settings, "ORG_EMAIL_DOMAINS", [])
        if not org_domains or "@" not in identifier:
            return identifier
        local_part, _, domain = identifier.rpartition("@")
        if cls.__domain_matches_org(domain, org_domains):
            return local_part
        return identifier

    @staticmethod
    def __is_account_locked(user_result):
        """nsaccountlock can come back as a bare bool, a string
        ('TRUE'/'FALSE'), or a single-item list wrapping either of those
        (ipalib's normalization here isn't perfectly consistent across
        attributes/versions) - or be entirely absent, which means NOT
        locked, since 389-ds only sets this attribute at all when an
        account IS locked. Normalize all of that into a real bool rather
        than trusting any one specific shape, which could otherwise let a
        locked account slip through as "active" (or vice versa) depending
        on exactly what shape came back."""
        value = user_result.get("nsaccountlock", False)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else False
        if isinstance(value, str):
            return value.strip().upper() == "TRUE"
        return bool(value)

    def __get_user(self, identifier):
        """Look up a FreeIPA user strictly by uid - direct login match, or
        an institutional email whose local part is stripped down to the
        uid by __strip_org_domain (since username always equals uid here).
        Deliberately NO fallback search by 'mail' or 'street' attribute:
        with the strict ORG_EMAIL_DOMAINS validation and username==uid
        convention in place, that search path is unreachable in real
        usage and only added attack surface (an unauthenticated,
        attribute-based user_find call) for no practical benefit. 'street'
        is still used elsewhere purely as the OTP DELIVERY address, never
        as a search/identification key.

        Returns the raw ipalib result dict; callers that need the
        canonical login should read result['uid'][0] rather than trusting
        whatever string the caller originally passed in."""
        lookup_uid = self.__strip_org_domain(identifier)
        try:
            user = self.__call_ipa(api.Command.user_show, uid=lookup_uid, all=True)
        except BackendError:
            raise
        except ipaerrors.NotFound:
            raise ValidateUserFailed("User not found")
        except Exception:
            logger.exception(f"Unexpected error looking up identifier={identifier!r}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)

        if self.__is_account_locked(user["result"]):
            raise ValidateUserFailed("Account is deactivated")

        return user

    # ---------------------------------------------------------------------
    # Token generation / validation
    # ---------------------------------------------------------------------

    @staticmethod
    def __gen_secure_token(length):
        # secrets.choice() - the module explicitly documented/intended for
        # this. Kept as a zero-padded string throughout (never cast to
        # int) so a token starting with '0' doesn't lose a digit of
        # entropy the way int(...) would collapse it.
        return "".join(secrets.choice("0123456789") for _ in range(length))

    @staticmethod
    def __hash_token(token):
        """Keyed hash (HMAC-SHA256) of an OTP, for storage in Redis instead
        of the plaintext code. This is defense in depth, not a strength
        upgrade on its own - a 6-digit numeric OTP is only ~1M possible
        values, so anyone who both reads this hash from Redis AND knows
        OTP_HASH_KEY could still brute-force it trivially fast. What this
        DOES close off: a passive read of Redis alone (a misconfigured
        instance, a backup, a replica, `redis-cli GET` in an operator's
        shell history, an accidental log capture) no longer hands over a
        directly usable code - it hands over something useless without
        also having the key. Constant-time comparison in __validate_token
        still applies to the resulting fixed-length hex digest either way."""
        return hmac.new(
            OTP_HASH_KEY.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def __check_and_bump_send_retry(self, identifier):
        """Rate-limits on the raw identifier the caller submitted, BEFORE
        any LDAP lookup happens - see module docs on enumeration safety."""
        retry_key = f"retry::send::{identifier}"
        retries = self.__redis_incr_with_ttl(retry_key, settings.LIMIT_TIME)
        if retries > settings.LIMIT_MAX_SEND:
            raise TooMuchRetries("Too many retries. Try later.")

    def __generate_and_store_token(self, uid):
        token_key = f"token::{uid}"
        token = self.__gen_secure_token(settings.TOKEN_LEN)
        # Store the hash, not the plaintext - see __hash_token docstring
        # for exactly what this does and doesn't protect against.
        self.__redis_set(
            token_key, self.__hash_token(token), ex=settings.TOKEN_LIFETIME
        )
        return token  # plaintext still returned - the caller needs it to actually deliver the code

    def __validate_token(self, uid, token):
        """Verifies the submitted token WITHOUT consuming it - consumption
        is a separate, explicit step (__consume_token) that the caller
        must invoke immediately after a successful verification and before
        doing anything else, so a failure later in the flow (bad password,
        IPA error) can't be exploited to reuse the same one-time code."""
        retry_key = f"retry::validate::{uid}"
        token_key = f"token::{uid}"

        current_retries = self.__redis_get(retry_key)
        if (
            current_retries is not None
            and int(current_retries) >= settings.LIMIT_MAX_VALIDATE_RETRY
        ):
            self.__redis_delete(token_key)
            raise TooMuchRetries("Too many retries. Request a new code.")

        stored_hash = self.__redis_get(token_key)

        token_matches = stored_hash is not None and secrets.compare_digest(
            self.__hash_token(str(token)), stored_hash
        )

        if token_matches:
            return True

        retries = self.__redis_incr_with_ttl(retry_key, settings.TOKEN_LIFETIME)
        if retries >= settings.LIMIT_MAX_VALIDATE_RETRY:
            self.__redis_delete(token_key)
        raise InvalidToken("You entered an incorrect or expired code")

    def __consume_token(self, uid):
        """Deletes the token and its validate-retry counter. Called only
        AFTER a password change has actually succeeded (see second_phase) -
        NOT immediately on OTP verification, so that a password-complexity
        failure doesn't strand the user with a "used up" code they still
        have correctly sitting in their inbox."""
        self.__redis_delete(f"token::{uid}", f"retry::validate::{uid}")

    def __acquire_reset_session(self, uid):
        """Short-lived, single-holder claim representing 'this uid's OTP
        has been verified and a password-change attempt is currently in
        flight'. This is what makes deferred consumption safe: without it,
        two requests bearing the same still-valid (not yet consumed) OTP -
        a double-submit, a replayed request, or a genuine race - could both
        proceed past verification at once. Only the first to acquire this
        lock is allowed to attempt the actual password change; a second,
        concurrent attempt is rejected outright rather than racing IPA."""
        key = f"reset_session::{uid}"
        try:
            acquired = self.redis.set(key, "1", nx=True, ex=RESET_SESSION_TTL)
        except redis.RedisError as e:
            logger.error(f"Redis SET NX failed for key={key!r}: {e}")
            raise BackendError(GENERIC_BACKEND_MESSAGE)
        if not acquired:
            raise TooMuchRetries(
                "A password reset is already in progress for this account. Please wait a moment and try again."
            )

    def __release_reset_session(self, uid):
        self.__redis_delete(f"reset_session::{uid}")

    def __invalidate_token(self, uid):
        """Full cleanup - used when abandoning a reset attempt entirely
        (first_phase failure), as opposed to __consume_token's narrower
        cleanup on a successful password change."""
        self.__redis_delete(
            f"token::{uid}", f"retry::send::{uid}", f"retry::validate::{uid}"
        )

    # ---------------------------------------------------------------------
    # Public two-phase flow
    # ---------------------------------------------------------------------

    def first_phase(self, identifier, provider_id):
        """Returns the canonical FreeIPA uid on success, which the caller
        should carry forward into second_phase instead of re-using
        whatever the user originally typed (which may have been an
        alternate email, not the real login).

        On any failure this raises GenericResetFailure (or TooMuchRetries,
        or InvalidIdentifierDomain, both of which are safe to distinguish -
        see their own docstrings) and never reveals which specific thing
        went wrong beyond that."""
        # Pure format check, no Redis/IPA touched - reject obviously
        # out-of-scope input before spending any resources on it.
        self.__validate_identifier_domain(identifier)

        self.__check_and_bump_send_retry(identifier)

        canonical_uid = identifier
        start = time.monotonic()
        try:
            try:
                user = self.__get_user(identifier)
                canonical_uid = user["result"]["uid"][0]

                if provider_id not in settings.PROVIDERS:
                    raise InvalidProvider("Specified provider does not exist")

                provider_conf = settings.PROVIDERS[provider_id]
                if not provider_conf.get("enabled", False):
                    raise InvalidProvider("Specified provider disabled")

                token = self.__generate_and_store_token(canonical_uid)

                provider_class = provider_conf["class"]
                provider = provider_class(provider_conf["options"])
                provider.send_token(user, token)

            except EmailValidateFailed as e:
                # Deliberate, narrow exception to the enumeration-safety
                # rule below: this message was written to be shown
                # directly to the user (it names a helpdesk contact) and
                # only fires for accounts that exist but have no usable
                # delivery channel. Revealing it does confirm the account
                # exists - accepted so a genuinely locked-out person gets
                # actionable guidance instead of silence. It's still
                # gated by the send-retry rate limit above, so it isn't
                # free to enumerate at scale. Every OTHER failure mode
                # here stays fully generic.
                logger.warning(
                    f"first_phase: no usable delivery channel for identifier={identifier!r}: {e}"
                )
                self.__invalidate_token(canonical_uid)
                raise
            except _EXPECTED_FIRST_PHASE_ERRORS as e:
                logger.warning(f"first_phase failed for identifier={identifier!r}: {e}")
                self.__invalidate_token(canonical_uid)
                raise GenericResetFailure()
            except Exception:
                logger.exception(
                    f"Unexpected error in first_phase for identifier={identifier!r}"
                )
                self.__invalidate_token(canonical_uid)
                raise GenericResetFailure()

            return canonical_uid
        finally:
            # Pads EVERY outcome from this point - success, EmailValidateFailed,
            # and GenericResetFailure alike - to take at least
            # MIN_FIRST_PHASE_DURATION wall-clock time. Deliberately does NOT
            # wrap __validate_identifier_domain/__check_and_bump_send_retry
            # above: those two already produce their own distinguishable,
            # safe-to-show messages (InvalidIdentifierDomain, TooMuchRetries),
            # so equalizing their timing adds no protection - it would just
            # make legitimate rate-limit/format-error responses slower for
            # no benefit.
            elapsed = time.monotonic() - start
            remaining = MIN_FIRST_PHASE_DURATION - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def second_phase(self, identifier, token, new_password):
        """Single-submit flow (OTP + new password + confirm all posted
        together): verify -> validate password -> change password ->
        consume OTP. Consumption happens LAST, only after a real success,
        so a password-complexity failure lets the user resubmit with a
        corrected password using the SAME code still sitting in their
        inbox, instead of forcing them to request an entirely new one.

        Deferring consumption reopens a small replay window - the token is
        verified-but-still-valid while a password change is in flight - so
        __acquire_reset_session() claims exclusive rights to complete this
        specific reset before anything else happens. A concurrent request
        (double-submit, replay, race) bearing the same valid token is
        rejected while the first is in flight, rather than both racing to
        change the password. The lock is released whichever way the
        attempt ends, so a failed attempt can be retried immediately and a
        successful one is left fully cleaned up.

        identifier should normally already be the canonical uid returned
        by first_phase, but we resolve it again here defensively - this
        endpoint can be reached directly without ever going through
        first_phase, so it has to stay enumeration-safe on its own."""
        self.__validate_identifier_domain(identifier)

        try:
            user = self.__get_user(identifier)
            uid = user["result"]["uid"][0]
        except Exception:
            raise InvalidToken("You entered an incorrect code")

        self.__validate_token(uid, token)
        self.__acquire_reset_session(uid)
        try:
            self.__validate_password(new_password, uid=uid)
            self.__set_password(uid, new_password)
            self.__consume_token(uid)
        finally:
            self.__release_reset_session(uid)

    def change_password(self, identifier, old_password, new_password):
        """Known-password change flow - separate from the OTP-based
        first_phase/second_phase reset flow above. Uses IPA's own
        current_password mechanism (api.Command.passwd with both
        password and current_password set), which is the FreeIPA-native
        self-service path: unlike __set_password's admin-context write
        (used by the reset flow, where the caller can't prove they know
        the existing password), supplying a matching current_password
        here makes IPA treat this as a genuine self-change, which means
        the server's OWN password-quality validation actually runs - the
        __validate_password() pre-check below is still done for a fast,
        friendly error message, but IPA is no longer relying on it alone
        the way the reset flow effectively has to.

        Deliberately enumeration-safe the simple way a login form is:
        "no such user" and "wrong current password" produce the exact
        same generic message, since correctly guessing someone's current
        password isn't something a username-enumeration attack helps
        with anyway - there's no separate narrow-disclosure case to carve
        out here the way EmailValidateFailed needed one in the reset flow.

        Rate-limited at the app level (independent of the reset flow's
        limiters) AND relies on FreeIPA's own account lockout policy
        (krbpwdmaxfailure/krbpwdlockoutduration) kicking in from the same
        wrong-password attempts, since current_password verification goes
        through the same directory password-check path IPA uses for
        normal authentication. Worth confirming empirically against your
        own IPA version that failed current_password attempts here do in
        fact increment krbLoginFailedCount the same way a failed kinit
        does - the app-level limiter below doesn't depend on that being
        true, but if it isn't, you're relying on this limiter alone."""
        self.__validate_identifier_domain(identifier)

        retry_key = f"retry::change::{identifier}"
        retries = self.__redis_incr_with_ttl(
            retry_key, settings.CHANGE_PASSWORD_LIMIT_TIME
        )
        if retries > settings.CHANGE_PASSWORD_MAX_ATTEMPTS:
            raise TooMuchRetries("Too many attempts. Please try again later.")

        try:
            user = self.__get_user(identifier)
            uid = user["result"]["uid"][0]
        except Exception as e:
            logger.warning(
                f"change_password: user resolution failed for identifier={identifier!r}: {e}"
            )
            raise ValidateUserFailed("Invalid username or current password.")

        self.__validate_password(new_password, uid=uid)

        try:
            self.__call_ipa(
                api.Command.passwd,
                uid=uid,
                password=new_password,
                current_password=old_password,
            )
        except BackendError:
            raise
        except ipaerrors.ExecutionError as e:
            if "password" in str(e).lower() and "policy" in str(e).lower():
                raise SetPasswordFailed(f"Password policy violation: {e}")
            logger.warning(
                f"change_password: current password check failed for uid={uid!r}: {e}"
            )
            raise ValidateUserFailed("Invalid username or current password.")
        except (ipaerrors.ValidationError, ipaerrors.ACIError) as e:
            logger.warning(
                f"change_password: current password rejected for uid={uid!r}: {e}"
            )
            raise ValidateUserFailed("Invalid username or current password.")
        except Exception:
            logger.exception(f"Unexpected error changing password for uid={uid!r}")
            raise SetPasswordFailed("Unexpected error changing password.")

        # Success - clear the attempt counter so a legitimate user isn't
        # penalized by prior mistyped attempts once they get it right.
        self.__redis_delete(retry_key)


def get_providers():
    return [
        {"id": key, "display_name": value["display_name"]}
        for key, value in settings.PROVIDERS.items()
        if value.get("enabled")
    ]
