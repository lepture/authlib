import time
from authlib.specs.rfc6749 import InvalidRequestError
from authlib.specs.rfc6749.util import scope_to_list
from authlib.specs.rfc7519 import JWT
from authlib.common.encoding import to_unicode
from ..util import create_half_hash


class OpenIDMixin(object):
    RESPONSE_TYPES = []

    @classmethod
    def check_authorization_endpoint(cls, request):
        if is_openid_request(request, cls.RESPONSE_TYPES):
            # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            wrap_openid_request(request)
            return True

    def validate_nonce(self, required=False):
        nonce = self.request.nonce
        if not nonce:
            if required:
                raise InvalidRequestError(
                    'Missing "nonce" in request.'
                )
            return True
        if not hasattr(self.server, 'exists_nonce'):
            raise RuntimeError(
                'The "AuthorizationServer" MUST define '
                'an "exists_nonce" method.'
            )
        if self.server.exists_nonce(nonce, self.request):
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


def is_openid_request(request, response_types):
    if request.response_type not in response_types:
        return False
    return 'openid' in scope_to_list(request.scope)


def wrap_openid_request(request):
    request._data_keys.update({
        'response_mode', 'nonce', 'display', 'prompt', 'max_age',
        'ui_locales', 'id_token_hint', 'login_hint', 'acr_values'
    })


SESSION_KEY_FORMAT = '_openid_{}'


def generate_id_token(token, profile, config, session, aud=None, code=None):
    now = int(time.time())
    payload = {
        'iss': config['jwt_iss'],
        'iat': now,
        'exp': now + token['expires_in'],
    }
    if aud:
        payload['aud'] = aud

    if session:
        nonce_key = SESSION_KEY_FORMAT.format('nonce')
        nonce = session.pop(nonce_key, None)
        if nonce:
            payload['nonce'] = nonce
        auth_time_key = SESSION_KEY_FORMAT.format('auth_time')
        auth_time = session.pop(auth_time_key, None)
        if auth_time:
            payload['auth_time'] = auth_time

    # calculate at_hash
    alg = config.get('jwt_alg', 'HS256')
    at_hash = to_unicode(create_half_hash(token['access_token'], alg))
    payload['at_hash'] = at_hash

    # calculate c_hash
    if code:
        payload['c_hash'] = to_unicode(create_half_hash(code, alg))

    payload.update(profile)
    jwt = JWT(algorithms=[alg])
    header = {'alg': alg}
    key = config['jwt_key']
    id_token = jwt.encode(header, payload, key)
    return to_unicode(id_token)
