from authlib.specs.rfc6749.grants import ImplicitGrant
from .base import OpenIDMixin


class OpenIDImplicitGrant(ImplicitGrant, OpenIDMixin):
    RESPONSE_TYPES = ['id_token token', 'id_token']

    def validate_authorization_request(self):
        super(OpenIDImplicitGrant, self).validate_authorization_request()
        self.validate_nonce(required=True)
