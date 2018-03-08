import logging
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from authlib.specs.rfc6749 import AccessDeniedError
from authlib.common.urls import add_params_to_uri
from .base import is_openid_request, wrap_openid_request
from .base import OpenIDMixin

log = logging.getLogger(__name__)


class OpenIDHybridGrant(OpenIDMixin, AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']
    RESPONSE_TYPES = ['code id_token', 'code token', 'code id_token token']

    @classmethod
    def check_authorization_endpoint(cls, request):
        if is_openid_request(request, cls.RESPONSE_TYPES):
            wrap_openid_request(request)
            return True

    def validate_authorization_request(self):
        super(OpenIDHybridGrant, self).validate_authorization_request()
        self.validate_nonce(required=False)

    def create_authorization_response(self, grant_user):
        state = self.request.state
        if grant_user:
            self.request.user = grant_user
            client = self.request.client

            code = self.create_authorization_code(
                client, grant_user, self.request)
            params = [('code', code)]

            token = self.generate_token(
                client, 'implicit',
                scope=self.request.scope,
                include_refresh_token=False
            )

            response_types = self.request.response_type.split()
            if 'token' in response_types:
                log.debug('Grant token {!r} to {!r}'.format(token, client))
                self.server.save_token(token, self.request)
                if 'id_token' in response_types:
                    token = self.process_implicit_token(
                        token, self.request, code)
            else:
                # response_type is "code id_token"
                token = {
                    'expires_in': token['expires_in'],
                    'scope': token['scope']
                }
                token = self.process_implicit_token(token, self.request, code)

            params.extend([(k, token[k]) for k in token])
            if state:
                params.append(('state', state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

        uri = add_params_to_uri(self.redirect_uri, params)
        headers = [('Location', uri)]
        return 302, '', headers

    def process_implicit_token(self, token, request, code):
        id_token = self.generate_id_token(
            token, request,
            nonce=request.nonce,
            code=code,
        )
        token['id_token'] = id_token
        return token

    def process_token(self, token, request):
        credential = request.credential
        id_token = self.generate_id_token(
            token, request,
            nonce=credential.get_nonce(),
            auth_time=credential.get_auth_time(),
        )
        if id_token:
            token['id_token'] = id_token
        return token
