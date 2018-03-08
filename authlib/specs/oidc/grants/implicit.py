import time
import logging
from authlib.specs.rfc6749.grants import ImplicitGrant
from authlib.specs.rfc6749.util import scope_to_list
from authlib.specs.rfc6749 import AccessDeniedError
from authlib.common.urls import add_params_to_uri
from .base import is_openid_request, generate_id_token, wrap_openid_request
from .base import OpenIDMixin

log = logging.getLogger(__name__)


class OpenIDImplicitGrant(OpenIDMixin, ImplicitGrant):
    RESPONSE_TYPES = ['id_token token', 'id_token']

    @classmethod
    def check_authorization_endpoint(cls, request):
        if is_openid_request(request, cls.RESPONSE_TYPES):
            # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            wrap_openid_request(request)
            return True

    def validate_authorization_request(self):
        super(OpenIDImplicitGrant, self).validate_authorization_request()
        self.validate_nonce(required=True)

    def create_authorization_response(self, grant_user):
        state = self.request.state
        if grant_user:
            self.request.user = grant_user
            client = self.request.client
            token = self.generate_token(
                client, self.GRANT_TYPE,
                scope=self.request.scope,
                include_refresh_token=False
            )
            if self.request.response_type == 'id_token':
                token = {'expires_in': token['expires_in']}
                token = self.process_token(token, self.request)
            else:
                log.debug('Grant token {!r} to {!r}'.format(token, client))
                self.server.save_token(token, self.request)
                token = self.process_token(token, self.request)
            params = [(k, token[k]) for k in token]
            if state:
                params.append(('state', state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

        uri = add_params_to_uri(self.redirect_uri, params, fragment=True)
        headers = [('Location', uri)]
        return 302, '', headers

    def process_token(self, token, request):
        # OpenID Connect authorization code flow
        scopes = scope_to_list(self.request.scope)
        # TODO: merge scopes and claims
        profile = self.generate_user_claims(request.user, scopes)

        id_token = generate_id_token(
            token, profile,
            config=self.server.config,
            aud=[request.client_id],
            nonce=request.nonce,
            auth_time=int(time.time())
        )
        token['id_token'] = id_token
        return token
