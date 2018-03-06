
from authlib.specs.rfc6749.grants import ImplicitGrant as _ImplicitGrant
from .base import OpenIDMixin


class ImplicitGrant(_ImplicitGrant, OpenIDMixin):
    RESPONSE_TYPES = ['id_token token', 'id_token']

    def validate_authorization_request(self):
        self.prepare_authorization_request()
        super(ImplicitGrant, self).validate_authorization_request()
        self.validate_nonce(required=True)
