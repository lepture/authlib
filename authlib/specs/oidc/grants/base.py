import time
import random
from authlib.specs.rfc6749 import InvalidRequestError
from authlib.specs.rfc6749.util import scope_to_list
from authlib.specs.rfc7519 import JWT
from authlib.common.encoding import to_native
from authlib.common.urls import add_params_to_uri, quote_url
from ..claims import UserInfo
from ..util import create_half_hash
from ..errors import (
    LoginRequiredError,
    AccountSelectionRequiredError,
    ConsentRequiredError,
)


class OpenIDMixin(object):
    SPECIFICATION = 'oidc'
    RESPONSE_TYPES = []

    def validate_prompt(self, end_user):
        prompt = self.request.prompt
        if not prompt:
            if not end_user:
                self.prompt = 'login'
            return self

        if prompt == 'none' and not end_user:
            raise LoginRequiredError()

        prompts = prompt.split()
        if 'none' in prompts and len(prompts) > 1:
            # If this parameter contains none with any other value,
            # an error is returned
            raise InvalidRequestError('Invalid "prompt" parameter.')

        if not end_user and 'login' in prompts:
            self.prompt = 'login'
            return self

        if 'consent' in prompts:
            if end_user:
                self.prompt = 'consent'
            else:
                raise ConsentRequiredError()
        elif 'select_account' in prompts:
            if end_user:
                self.prompt = 'select_account'
            else:
                raise AccountSelectionRequiredError()
        return self

    def validate_authorization_redirect_uri(self, client):
        if not self.redirect_uri:
            raise InvalidRequestError(
                'Missing "redirect_uri" in request.',
            )

        if not client.check_redirect_uri(self.redirect_uri):
            raise InvalidRequestError(
                'Invalid "redirect_uri" in request.',
                state=self.request.state,
            )

    def validate_nonce(self, required=False):
        nonce = self.request.nonce
        if not nonce:
            if required:
                raise InvalidRequestError(
                    'Missing "nonce" in request.'
                )
            return True

        if self.server.execute_hook('exists_nonce', nonce, self.request):
            raise InvalidRequestError('Replay attack')

    def generate_user_info(self, user, scopes):
        # OpenID Connect authorization code flow
        user_info = user.generate_user_info(scopes)
        if not isinstance(user_info, UserInfo):
            raise RuntimeError(
                'generate_user_info should return UserInfo instance.')

        if 'sub' not in user_info:
            user_info['sub'] = str(user.get_user_id())
        return user_info

    def generate_id_token(self, token, request, nonce=None,
                          auth_time=None, code=None):
        scopes = scope_to_list(token['scope'])
        if not scopes or scopes[0] != 'openid':
            return None

        # TODO: merge scopes and claims
        user_info = self.generate_user_info(request.user, scopes)

        now = int(time.time())
        if auth_time is None:
            auth_time = now

        config = self.server.config
        payload = {
            'iss': config['jwt_iss'],
            'aud': [request.client.client_id],
            'iat': now,
            'exp': now + config['jwt_exp'],
            'auth_time': auth_time,
        }
        if nonce:
            payload['nonce'] = nonce

        # calculate at_hash
        alg = config['jwt_alg']

        access_token = token.get('access_token')
        if access_token:
            payload['at_hash'] = to_native(create_half_hash(access_token, alg))

        # calculate c_hash
        if code:
            payload['c_hash'] = to_native(create_half_hash(code, alg))

        payload.update(user_info)
        jwt = JWT(algorithms=alg)
        header = {'alg': alg}

        key = config['jwt_key']
        if isinstance(key, dict):
            # JWK set format
            if 'keys' in key:
                key = random.choice(key['keys'])
                header['kid'] = key['kid']
            elif 'kid' in key:
                header['kid'] = key['kid']

        return to_native(jwt.encode(header, payload, key))


def is_openid_request(request):
    scopes = scope_to_list(request.scope)
    # openid should be the first scope
    return scopes and scopes[0] == 'openid'


def wrap_openid_request(request):
    request._data_keys.update({
        'response_mode', 'nonce', 'display', 'prompt', 'max_age',
        'ui_locales', 'id_token_hint', 'login_hint', 'acr_values'
    })


def create_response_mode_response(redirect_uri, params, response_mode=None):
    if response_mode is None:
        response_mode = 'fragment'

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
        return tpl.format(quote_url(redirect_uri), inputs)

    if response_mode == 'query':
        uri = add_params_to_uri(redirect_uri, params, fragment=False)
    elif response_mode == 'fragment':
        uri = add_params_to_uri(redirect_uri, params, fragment=True)
    else:
        raise InvalidRequestError('Invalid "response_mode" value')

    return 302, '', [('Location', uri)]
