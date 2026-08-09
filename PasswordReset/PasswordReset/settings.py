import os
from pathlib import Path

import app.providers
import environ

env = environ.Env()
environ.Env.read_env()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = env("SECRET_KEY")
DEBUG = False

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["*"])
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=True)
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=True)
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# Applications
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "app",
]

# Middleware
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "PasswordReset.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                #'django.template.context_processors.settings',
            ],
            "builtins": ["django.templatetags.static"],
        },
    },
]

WSGI_APPLICATION = "PasswordReset.wsgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        # Activated by passing user=SimpleNamespace(username=uid, ...) to
        # validate_password() in __validate_password - without a user
        # object this validator silently no-ops.
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    # Deliberately NO MinimumLengthValidator here - length is enforced
    # against FreeIPA's LIVE policy (krbpwdminlength) in
    # PasswdManager.__validate_password, not a hardcoded value. A
    # hardcoded floor here could silently diverge from real IPA policy if
    # it's ever changed - exactly the class of bug already fixed once in
    # this codebase (see __validate_password's krbpwdminlength handling).
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
    {
        # Have I Been Pwned check via k-anonymity - no API key needed.
        # Falls back to CommonPasswordValidator (already listed above) on
        # any API error/timeout, so an HIBP outage never blocks a
        # legitimate password change.
        "NAME": "pwned_passwords_django.validators.PwnedPasswordsValidator",
        "OPTIONS": {
            # Tuple form (singular, plural) is REQUIRED for %(amount)d
            # substitution to work - every documented example pairing
            # %(amount)d with a custom message uses this exact shape.
            "error_message": (
                "This password has appeared in a data breach %(amount)d time. Please choose a different password.",
                "This password has appeared in data breaches %(amount)d times. Please choose a different password.",
            ),
            "help_message": "Your password can't be a commonly used or previously breached password.",
        },
    },
]

# Internationalisation
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Kampala"
USE_I18N = True
# USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, images)
STATIC_URL = "/static/"

# Directory where collectstatic will gather all static files
STATIC_ROOT = BASE_DIR / "staticfiles"

# Local static file directories (used in development)
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

# Default primary key field type (important for Django 3.2+)
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Redis settings
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None

# Kerberos / LDAP Integration
LDAP_USER = "ldap-passwd-reset"
KEYTAB_PATH = os.path.join(BASE_DIR, "ldap-passwd-reset.keytab")

# Token Settings
TOKEN_LEN = 6
TOKEN_LIFETIME = 300  # 5 minutes

# Cloudflare Turnstile Settings
TURNSTILE_SITE_KEY = env("TURNSTILE_SITE_KEY", default="")
TURNSTILE_SECRET_KEY = env("TURNSTILE_SECRET_KEY", default="")

# Have I Been Pwned - Pwned Passwords check (k-anonymity, no API key
# needed). Enabled by default; fails open on any network/API error so an
# HIBP outage can never block a legitimate reset. Set HIBP_ENABLED=False
# in .env to disable if outbound HTTPS to api.pwnedpasswords.com isn't
# available from this server.
HIBP_ENABLED = env.bool("HIBP_ENABLED", default=True)
HIBP_TIMEOUT = env.float("HIBP_TIMEOUT", default=3.0)

# Wire HIBP_TIMEOUT into pwned-passwords-django
PWNED_PASSWORDS = {
    "API_TIMEOUT": HIBP_TIMEOUT,
    "ADD_PADDING": True,
}
PWNED_PASSWORDS_API_TIMEOUT = HIBP_TIMEOUT

# If someone enters their institutional email (username@one of these
# domains, or any subdomain of one) instead of their bare username, strip
# the domain so a direct uid lookup matches - e.g. 'jdoe@ucu.ac.ug' or
# 'jdoe@staff.ucu.ac.ug' -> 'jdoe'. Comma-separated in .env, e.g.:
#   ORG_EMAIL_DOMAINS=ucu.ac.ug,partner-org.ug
# See __domain_matches_org() in pwdmanager.py for exact matching rules.
ORG_EMAIL_DOMAINS = env.list("ORG_EMAIL_DOMAINS", default=["ucu.ac.ug"])

# Per gunicorn WORKER PROCESS, not a single number across the whole
# service - sync workers are separate OS processes, each importing this
# app (and building its own REDIS_POOL) independently, so the real total
# across the service is roughly (gunicorn --workers) * this value. A sync
# worker only ever has one request in flight at a time, needing at most a
# couple of Redis round trips concurrently - not dozens - so this is
# intentionally modest rather than the redis-py default of 2**31.
# With --workers 3 (see the systemd unit), that's ~30 connections total
# at peak, comfortably under Redis's own default maxclients (10000).
REDIS_MAX_CONNECTIONS = env.int("REDIS_MAX_CONNECTIONS", default=10)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        # goes to stdout/stderr - captured by journald under the systemd
        # unit (StandardOutput=journal / StandardError=journal), so
        # `journalctl -u ldap-passwd-reset` shows this without any extra
        # file management.
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        # Covers app.pwdmanager, app.views, app.providers - all use
        # logging.getLogger(__name__), which nests under 'app'.
        "app": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
LIMIT_MAX_VALIDATE_RETRY = 5
LIMIT_MAX_SEND = 3
LIMIT_TIME = 86400

# Change-password flow (known current password, not the OTP reset flow).
# App-level limiter on wrong-current-password attempts, deliberately on a
# shorter window than the OTP send limiter above - this is closer to a
# login-attempt throttle than a "don't spam email" throttle. Values chosen
# to roughly track your own FreeIPA policy (krbpwdmaxfailure=5,
# krbpwdlockoutduration=600) so the app-level and IPA-level limits kick in
# around the same order of magnitude, rather than one being wildly looser
# than the other.
CHANGE_PASSWORD_MAX_ATTEMPTS = 5
CHANGE_PASSWORD_LIMIT_TIME = 600

# Reset code delivery. Email-only by design - SMS was deliberately left
# disabled/unused (SIM-swap risk), and Signal/Slack were never enabled.
# The provider classes themselves still exist in providers.py if this ever
# needs to change, but the config only wires up what's actually in use.
PROVIDERS = {
    "email-1": {
        "class": app.providers.Email,
        "enabled": True,
        "display_name": "Email",
        "options": {
            "ldap_attribute_name": "street",  # <== use 'street' instead of 'mail'
            "msg_template": (
                "Dear {full_name},\n\n"
                "We received a request to reset the password for your UCU account.\n\n"
                "Your password reset token is: {token}\n"
                "This token will expire in 5 minutes. Please use it promptly to complete your password reset.\n\n"
                "If you did not request this password reset, you can safely ignore this email. "
                "Your password will remain unchanged unless the reset process is completed. "
                "If you believe this request was unauthorised, please contact University ICT Services (UIS).\n\n"
                "Thank you,\n\n"
                "University ICT Services (UIS)"
            ),
            "msg_subject": "UCU Password Reset Token",
            "smtp_from": env("SMTP_FROM"),
            "smtp_user": env("SMTP_USER"),
            "smtp_pass": env("SMTP_PASS"),
            "smtp_server_addr": env("SMTP_SERVER_ADDR"),
            "smtp_server_port": env.int("SMTP_SERVER_PORT"),
            "smtp_server_tls": True,
        },
    },
}
