from authlib.specs.rfc6749.grants import ImplicitGrant
from authlib.specs.rfc6749.util import scope_to_list
from .base import OpenIDMixin, generate_id_token


class OpenIDImplicitGrant(ImplicitGrant, OpenIDMixin):
    RESPONSE_TYPES = ['id_token token', 'id_token']

    def __init__(self, request, server):
        super(OpenIDImplicitGrant, self).__init__(request, server)
        self.session = None

    def validate_authorization_request(self):
        super(OpenIDImplicitGrant, self).validate_authorization_request()
        self.validate_nonce(required=True)

    def generate_id_token(self, token, client, profile):
        return generate_id_token(
            token, profile,
            config=self.server.config,
            session=self.session,
            aud=[client.client_id],
        )

    def process_token(self, token, client, user):
        # OpenID Connect authorization code flow
        scopes = scope_to_list(self.request.scope)
        # TODO: merge scopes and claims
        profile = self.generate_user_claims(user, scopes)

        id_token = generate_id_token(
            token, profile,
            config=self.server.config,
            session=self.session,
            aud=[client.client_id],
        )
        token['id_token'] = id_token
        return token
