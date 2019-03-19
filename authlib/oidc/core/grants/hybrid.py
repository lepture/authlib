import logging
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749 import AccessDeniedError, InvalidScopeError
from .util import (
    is_openid_scope,
    create_response_mode_response,
    generate_id_token,
)
from .code import OpenIDCode

log = logging.getLogger(__name__)


class OpenIDHybridGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']
    RESPONSE_TYPES = ['code id_token', 'code token', 'code id_token token']
    DEFAULT_RESPONSE_MODE = 'fragment'

    def __init__(self, *args, **kwargs):
        super(OpenIDHybridGrant, self).__init__(*args, **kwargs)
        config = self.server.config
        extension = OpenIDCode(
            key=config['jwt_key'],
            alg=config['jwt_alg'],
            iss=config['jwt_iss'],
            exp=config['jwt_exp'],
            exists_nonce=self.exists_nonce,
            required_nonce=True,
        )
        extension(self)

    @classmethod
    def check_authorization_endpoint(cls, request):
        if request.response_type in cls.RESPONSE_TYPES:
            return True

    def validate_authorization_request(self):
        if not is_openid_scope(self.request.scope):
            raise InvalidScopeError('Missing "openid" scope')
        super(OpenIDHybridGrant, self).validate_authorization_request()

    def exists_nonce(self, nonce, request):  # pragma: no cover
        return self.server.execute_hook('exists_nonce', nonce, request)

    def create_authorization_response(self, grant_user):
        state = self.request.state
        if grant_user:
            params = self._create_granted_params(grant_user)
            if state:
                params.append(('state', state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

        # http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
        response_mode = self.request.data.get('response_mode', self.DEFAULT_RESPONSE_MODE)
        return create_response_mode_response(
            redirect_uri=self.redirect_uri,
            params=params,
            response_mode=response_mode,
        )

    def _create_granted_params(self, grant_user):
        self.request.user = grant_user
        client = self.request.client

        code = self.create_authorization_code(
            client, grant_user, self.request)
        params = [('code', code)]

        token = self.generate_token(
            client, 'implicit',
            user=grant_user,
            scope=self.request.scope,
            include_refresh_token=False
        )

        response_types = self.request.response_type.split()
        if 'token' in response_types:
            log.debug('Grant token %r to %r', token, client)
            self.server.save_token(token, self.request)
            if 'id_token' in response_types:
                token = self._process_implicit_token(token, code)
        else:
            # response_type is "code id_token"
            token = {
                'expires_in': token['expires_in'],
                'scope': token['scope']
            }
            token = self._process_implicit_token(token, code)

        params.extend([(k, token[k]) for k in token])
        return params

    def _process_implicit_token(self, token, code):
        config = self.server.config
        key = config['jwt_key']
        alg = config['jwt_alg']
        iss = config['jwt_iss']
        exp = config['jwt_exp']

        request = self.request
        id_token = generate_id_token(
            key=key, token=token, request=request,
            alg=alg, iss=iss, exp=exp,
            nonce=request.data.get('nonce'),
            code=code,
        )
        token['id_token'] = id_token
        return token
