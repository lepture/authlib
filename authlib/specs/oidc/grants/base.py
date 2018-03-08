import time
from authlib.specs.rfc6749 import InvalidRequestError
from authlib.specs.rfc6749.util import scope_to_list
from authlib.specs.rfc7519 import JWT
from authlib.common.encoding import to_unicode
from ..util import create_half_hash


class OpenIDMixin(object):
    RESPONSE_TYPES = []

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

    def generate_user_claims(self, user, claims):
        if isinstance(claims, list):
            # TODO: scopes to claims
            claims = {}
        # OpenID Connect authorization code flow
        # TODO: define how to create user claims
        profile = user.generate_openid_claims(claims)
        if 'sub' not in profile:
            profile['sub'] = str(user.get_user_id())
        return profile

    def generate_id_token(self, token, request, nonce=None,
                          auth_time=None, code=None):

        scopes = scope_to_list(token['scope'])
        if not scopes or 'openid' not in scopes:
            return None

        # TODO: merge scopes and claims
        profile = self.generate_user_claims(request.user, scopes)

        now = int(time.time())
        if auth_time is None:
            auth_time = now

        config = self.server.config
        payload = {
            'iss': config['jwt_iss'],
            'aud': [request.client.client_id],
            'iat': now,
            'exp': now + token['expires_in'],
            'auth_time': auth_time,
        }
        if nonce:
            payload['nonce'] = nonce

        # calculate at_hash
        alg = config.get('jwt_alg', 'HS256')

        access_token = token.get('access_token')
        if access_token:
            at_hash = to_unicode(create_half_hash(access_token, alg))
            payload['at_hash'] = at_hash

        # calculate c_hash
        if code:
            payload['c_hash'] = to_unicode(create_half_hash(code, alg))

        payload.update(profile)
        jwt = JWT(algorithms=alg)
        header = {'alg': alg}
        key = config['jwt_key']
        id_token = jwt.encode(header, payload, key)
        return to_unicode(id_token)


def is_openid_request(request, response_types):
    if request.response_type not in response_types:
        return False
    return 'openid' in scope_to_list(request.scope)


def wrap_openid_request(request):
    request._data_keys.update({
        'response_mode', 'nonce', 'display', 'prompt', 'max_age',
        'ui_locales', 'id_token_hint', 'login_hint', 'acr_values'
    })
