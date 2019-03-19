import logging
from authlib.oauth2.rfc6749.grants import ImplicitGrant
from authlib.oauth2.rfc6749 import InvalidScopeError, AccessDeniedError
from .util import (
    is_openid_scope,
    validate_nonce,
    validate_request_prompt,
    create_response_mode_response,
    generate_id_token,
)

log = logging.getLogger(__name__)


class OpenIDImplicitGrant(ImplicitGrant):
    RESPONSE_TYPES = ['id_token token', 'id_token']
    DEFAULT_RESPONSE_MODE = 'fragment'

    @classmethod
    def check_authorization_endpoint(cls, request):
        if request.response_type in cls.RESPONSE_TYPES:
            return True

    def validate_authorization_request(self):
        if not is_openid_scope(self.request.scope):
            raise InvalidScopeError('Missing "openid" scope')
        super(OpenIDImplicitGrant, self).validate_authorization_request()
        validate_nonce(self.request, self.exists_nonce, required=True)

    def exists_nonce(self, nonce, request):  # pragma: no cover
        return self.server.execute_hook('exists_nonce', nonce, request)

    def validate_consent_request(self):
        self.validate_authorization_request()
        validate_request_prompt(self)

    def create_authorization_response(self, grant_user):
        state = self.request.state
        if grant_user:
            self.request.user = grant_user
            client = self.request.client
            token = self.generate_token(
                client, self.GRANT_TYPE,
                user=grant_user,
                scope=self.request.scope,
                include_refresh_token=False
            )
            if self.request.response_type == 'id_token':
                token = {
                    'expires_in': token['expires_in'],
                    'scope': token['scope'],
                }
                token = self._process_implicit_token(token)
            else:
                log.debug('Grant token %r to %r', token, client)
                self.server.save_token(token, self.request)
                token = self._process_implicit_token(token)
            params = [(k, token[k]) for k in token]
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

    def _process_implicit_token(self, token):
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
        )
        token['id_token'] = id_token
        return token
