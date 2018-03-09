"""
    authlib.specs.oidc.grants.code
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Authentication using the Authorization Code Flow
    per `Section 3.1`_.

    .. _`Section 3.1`: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from .base import OpenIDMixin, wrap_openid_request, is_openid_request

log = logging.getLogger(__name__)


class OpenIDCodeGrant(OpenIDMixin, AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']
    RESPONSE_TYPES = ['code']

    @classmethod
    def check_authorization_endpoint(cls, request):
        # OpenIDCodeGrant will act as AuthorizationCodeGrant
        return request.response_type == cls.RESPONSE_TYPE

    def validate_authorization_request(self):
        super(OpenIDCodeGrant, self).validate_authorization_request()
        if not is_openid_request(self.request):
            return
        wrap_openid_request(self.request)
        # validate openid request
        self.validate_nonce(required=False)

    def validate_prompt(self, end_user):
        if is_openid_request(self.request):
            super(OpenIDCodeGrant, self).validate_prompt(end_user)

    def process_token(self, token, request):
        scope = token.get('scope')
        if not scope or not scope.startswith('openid'):
            # standard authorization code flow
            return token

        credential = request.credential
        id_token = self.generate_id_token(
            token, request,
            nonce=credential.get_nonce(),
            auth_time=credential.get_auth_time(),
        )
        if id_token:
            token['id_token'] = id_token
        return token
