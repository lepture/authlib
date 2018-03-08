import logging
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from .base import is_openid_request, wrap_openid_request, generate_id_token
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
            # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
            wrap_openid_request(request)
            return True

    def process_token(self, token, client, user):
        profile = self.generate_user_claims(user, {})

        id_token = generate_id_token(
            token, profile,
            config=self.server.config,
            session=self.session,
            aud=[client.client_id],
        )
        token['id_token'] = id_token
        return token
