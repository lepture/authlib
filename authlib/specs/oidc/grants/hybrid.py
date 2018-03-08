import logging
import time
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from authlib.specs.rfc6749.util import scope_to_list
from .base import is_openid_request, generate_id_token, wrap_openid_request
from .base import OpenIDMixin

log = logging.getLogger(__name__)


class OpenIDHybridGrant(OpenIDMixin, AuthorizationCodeGrant):
    RESPONSE_TYPES = ['code id_token', 'code token', 'code id_token token']

    def __init__(self, request, server):
        super(OpenIDHybridGrant, self).__init__(request, server)
        self.session = None

    @classmethod
    def check_authorization_endpoint(cls, request):
        if is_openid_request(request, cls.RESPONSE_TYPES):
            wrap_openid_request(request)
            return True

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
