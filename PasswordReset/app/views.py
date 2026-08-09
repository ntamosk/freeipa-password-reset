import logging
import requests

from django.conf import settings
from django.contrib import messages
from django.shortcuts import render, redirect
from django.views import View

from .pwdmanager import (
    get_providers, PasswdManager, TooMuchRetries, GenericResetFailure,
    EmailValidateFailed, InvalidIdentifierDomain, ValidateUserFailed,
    SetPasswordFailed,
    TooMuchRetries,
    ValidateUserFailed,
    get_providers,
)

logger = logging.getLogger(__name__)

def verify_turnstile(request):
    """
    Validates the Cloudflare Turnstile token server-side.

    Fails OPEN (returns True) if Turnstile isn't configured at all, or if
    Cloudflare's own endpoint is unreachable/erroring - a third-party
    outage must never be able to block a legitimate password reset.
    Only returns False when the token is genuinely missing or Cloudflare
    explicitly rejected it.
    """
    if not (settings.TURNSTILE_SITE_KEY and settings.TURNSTILE_SECRET_KEY):
        return True  # not configured - don't block anything

    token = request.POST.get('cf-turnstile-response')
    if not token:
        return False  # genuinely missing - this IS a real rejection

    payload = {
        'secret': settings.TURNSTILE_SECRET_KEY,
        'response': token,
        'remoteip': request.META.get('REMOTE_ADDR'),
    }

    try:
        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data=payload,
            timeout=5
        )
        response.raise_for_status()
        return response.json().get('success', False)
    except requests.exceptions.RequestException as e:
        logger.warning(f"Turnstile verification unreachable/failed, failing open: {e}")
        return True  # infra error, not a real rejection - don't block
    except ValueError as e:
        logger.warning(f"Turnstile returned unparseable response, failing open: {e}")
        return True


def index(request):
    context = {
        'providers': get_providers(),
        'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
    }
    return render(request, 'index.html', context)


class GetToken(View):
    def post(self, request, *args, **kwargs):
        # 1. Verify Turnstile first
        if not verify_turnstile(request):
            context = {
                'msg': "Security verification failed. Please complete the check and try again.",
                'error': True,
                'providers': get_providers(),
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'index.html', context, status=200)

        raw_identifier = request.POST.get('uid')
        provider_id = request.POST.get('provider')

        try:
            canonical_uid = PasswdManager().first_phase(identifier=raw_identifier, provider_id=provider_id)
            request.session['reset_uid'] = canonical_uid
        except InvalidIdentifierDomain as e:
            context = {
                'msg': str(e),
                'error': True,
                'providers': get_providers(),
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'index.html', context, status=200)
        except TooMuchRetries:
            logger.warning(f"Rate limit hit for identifier={raw_identifier!r}")
            context = {
                'msg': "Too many requests. Please try again later.",
                'error': True,
                'providers': get_providers(),
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'index.html', context, status=200)
        except EmailValidateFailed as e:
            context = {
                'msg': str(e),
                'error': True,
                'providers': get_providers(),
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'index.html', context, status=200)
        except GenericResetFailure:
            request.session['reset_uid'] = raw_identifier
        except Exception as e:
            logger.error(f"Unexpected error escaped first_phase for identifier={raw_identifier!r}: {e}")
            request.session['reset_uid'] = raw_identifier

        return redirect('set_password')


class SetPassword(View):
    def get(self, request, *args, **kwargs):
        uid = request.session.get('reset_uid')
        if not uid:
            messages.error(request, "Session expired or invalid request. Please request a new code.")
            return redirect('index')

        context = {
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
        }
        return render(request, 'setpassword.html', context)

    def post(self, request, *args, **kwargs):
        # 1. Verify Turnstile first
        if not verify_turnstile(request):
            context = {
                'msg': "Security verification failed. Please complete the check and try again.",
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'setpassword.html', context, status=200)

        uid = request.session.get('reset_uid')
        if not uid:
            messages.error(request, "Session expired or invalid request. Please start over.")
            return redirect('index')

        token = request.POST.get('token')
        password = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password != password2:
            context = {
                'msg': "Passwords do not match.", 
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'setpassword.html', context, status=200)

        try:
            PasswdManager().second_phase(uid, token, password)
        except Exception as e:
            logger.error(f"Second phase error for uid={uid!r}: {str(e)}")
            context = {
                'msg': str(e),
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'setpassword.html', context, status=200)

        request.session.pop('reset_uid', None)
        messages.success(request, 'Your password has been successfully changed.')
        return redirect('index')


class ChangePassword(View):
    def get(self, request, *args, **kwargs):
        context = {
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
        }
        return render(request, 'changepassword.html', context)

    def post(self, request, *args, **kwargs):
        # 1. Verify Turnstile first
        if not verify_turnstile(request):
            context = {
                'msg': "Security verification failed. Please complete the check and try again.",
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'changepassword.html', context, status=200)

        uid = request.POST.get('uid')
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            context = {
                'msg': "New passwords do not match.", 
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'changepassword.html', context, status=200)

        try:
            PasswdManager().change_password(uid, old_password, new_password)
        except (TooMuchRetries, InvalidIdentifierDomain, ValidateUserFailed, SetPasswordFailed) as e:
            context = {
                'msg': str(e), 
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'changepassword.html', context, status=200)
        except Exception:
            logger.exception(f"Unexpected error in change_password for uid={uid!r}")
            context = {
                'msg': "An unexpected error occurred. Please try again later.",
                'error': True,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY,
            }
            return render(request, 'changepassword.html', context, status=200)

        messages.success(request, 'Password successfully changed.')
        return redirect('index')
