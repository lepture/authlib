"""
    authlib.specs.oidc.grants.code
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Authentication using the Authorization Code Flow
    per `Section 3.1`_.

    .. _`Section 3.1`: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from .base import OpenIDMixin


class OpenIDCodeGrant(AuthorizationCodeGrant, OpenIDMixin):
    RESPONSE_TYPES = ['code']

    def validate_authorization_request(self):
        super(OpenIDCodeGrant, self).validate_authorization_request()
        self.validate_nonce(required=False)
