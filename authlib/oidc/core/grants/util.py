import time
import random
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.jose import JWT
from authlib.common.encoding import to_native
from authlib.common.urls import add_params_to_uri, quote_url
from ..claims import UserInfo
from ..util import create_half_hash
from ..errors import (
    LoginRequiredError,
    AccountSelectionRequiredError,
    ConsentRequiredError,
)


def is_openid_scope(scope):
    scopes = scope_to_list(scope)
    return scopes and 'openid' in scopes


def validate_request_prompt(grant, redirect_uri, redirect_fragment=False):
    prompt = grant.request.data.get('prompt')
    end_user = grant.request.user
    if not prompt:
        if not end_user:
            grant.prompt = 'login'
        return grant

    if prompt == 'none' and not end_user:
        raise LoginRequiredError(
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment)

    prompts = prompt.split()
    if 'none' in prompts and len(prompts) > 1:
        # If this parameter contains none with any other value,
        # an error is returned
        raise InvalidRequestError(
            'Invalid "prompt" parameter.',
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment)

    prompt = _guess_prompt_value(
        end_user, prompts, redirect_uri, redirect_fragment=redirect_fragment)
    if prompt:
        grant.prompt = prompt
    return grant


def validate_nonce(request, exists_nonce, required=False):
    nonce = request.data.get('nonce')
    if not nonce:
        if required:
            raise InvalidRequestError(
                'Missing "nonce" in request.'
            )
        return True

    if exists_nonce(nonce, request):
        raise InvalidRequestError('Replay attack')


def generate_id_token(
        token, user_info, key, alg, iss, aud, exp,
        nonce=None, auth_time=None, code=None):

    payload = _generate_id_token_payload(
        alg=alg, iss=iss, aud=aud, exp=exp, nonce=nonce,
        auth_time=auth_time, code=code,
        access_token=token.get('access_token'),
    )
    payload.update(user_info)
    return _jwt_encode(alg, payload, key)


def create_response_mode_response(redirect_uri, params, response_mode):
    if response_mode == 'form_post':
        tpl = (
            '<html><head><title>Authlib</title></head>'
            '<body onload="javascript:document.forms[0].submit()">'
            '<form method="post" action="{}">{}</form></body></html>'
        )
        inputs = ''.join([
            '<input type="hidden" name="{}" value="{}"/>'.format(
                quote_url(k), quote_url(v))
            for k, v in params
        ])
        body = tpl.format(quote_url(redirect_uri), inputs)
        return 200, body, [('Content-Type', 'text/html; charset=utf-8')]

    if response_mode == 'query':
        uri = add_params_to_uri(redirect_uri, params, fragment=False)
    elif response_mode == 'fragment':
        uri = add_params_to_uri(redirect_uri, params, fragment=True)
    else:
        raise InvalidRequestError('Invalid "response_mode" value')

    return 302, '', [('Location', uri)]


def _guess_prompt_value(end_user, prompts, redirect_uri, redirect_fragment):
    # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    if not end_user and 'login' in prompts:
        return 'login'

    if 'consent' in prompts:
        if not end_user:
            raise ConsentRequiredError(
                redirect_uri=redirect_uri,
                redirect_fragment=redirect_fragment)
        return 'consent'
    elif 'select_account' in prompts:
        if not end_user:
            raise AccountSelectionRequiredError(
                redirect_uri=redirect_uri,
                redirect_fragment=redirect_fragment)
        return 'select_account'


def _generate_id_token_payload(
        alg, iss, aud, exp, nonce=None, auth_time=None,
        code=None, access_token=None):
    now = int(time.time())
    if auth_time is None:
        auth_time = now

    payload = {
        'iss': iss,
        'aud': aud,
        'iat': now,
        'exp': now + exp,
        'auth_time': auth_time,
    }
    if nonce:
        payload['nonce'] = nonce

    if code:
        payload['c_hash'] = to_native(create_half_hash(code, alg))

    if access_token:
        payload['at_hash'] = to_native(create_half_hash(access_token, alg))
    return payload


def _generate_user_info(user, scopes):  # pragma: no cover
    # OpenID Connect authorization code flow
    user_info = user.generate_user_info(scopes)
    if not isinstance(user_info, UserInfo):
        raise RuntimeError(
            'generate_user_info should return UserInfo instance.')

    if 'sub' not in user_info:
        user_info['sub'] = str(user.get_user_id())
    return user_info


def _jwt_encode(alg, payload, key):
    jwt = JWT(algorithms=alg)
    header = {'alg': alg}
    if isinstance(key, dict):
        # JWK set format
        if 'keys' in key:
            key = random.choice(key['keys'])
            header['kid'] = key['kid']
        elif 'kid' in key:
            header['kid'] = key['kid']

    return to_native(jwt.encode(header, payload, key))
