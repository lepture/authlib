"""
    authlib.specs.oidc.grants.code
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Authentication using the Authorization Code Flow
    per `Section 3.1`_.

    .. _`Section 3.1`: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from authlib.specs.rfc6749.util import scope_to_list
from .base import OpenIDMixin, generate_id_token, wrap_openid_request

log = logging.getLogger(__name__)


class OpenIDCodeGrant(OpenIDMixin, AuthorizationCodeGrant):
    RESPONSE_TYPES = ['code']

    @classmethod
    def check_authorization_endpoint(cls, request):
        # OpenIDCodeGrant will act as AuthorizationCodeGrant
        return request.response_type == cls.RESPONSE_TYPE

    def validate_authorization_request(self):
        super(OpenIDCodeGrant, self).validate_authorization_request()
        scopes = scope_to_list(self.request.scope) or []
        if 'openid' not in scopes:
            return
        wrap_openid_request(self.request)
        # validate openid request
        self.validate_nonce(required=False)

    def validate_consent_request(self, end_user):
        # TODO
        pass

    def process_token(self, token, request):
        scope = token.get('scope')
        scopes = scope_to_list(scope) or []
        if 'openid' not in scopes:
            # standard authorization code flow
            return token

        # OpenID Connect authorization code flow
        profile = self.generate_user_claims(request.user, scopes)
        credential = request.credential

        id_token = generate_id_token(
            token, profile,
            config=self.server.config,
            aud=[request.client.client_id],
            nonce=credential.get_nonce(),
            auth_time=credential.get_auth_time(),
        )
        token['id_token'] = id_token
        return token
