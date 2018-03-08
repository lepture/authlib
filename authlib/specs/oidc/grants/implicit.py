import time
from authlib.specs.rfc6749.grants import ImplicitGrant
from authlib.specs.rfc6749.util import scope_to_list
from .base import is_openid_request, wrap_openid_request, generate_id_token
from .base import OpenIDMixin


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
