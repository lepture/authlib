"""
    authlib.oidc.core.grants.code
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Authentication using the Authorization Code Flow
    per `Section 3.1`_.

    .. _`Section 3.1`: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging
from authlib.oauth2.rfc6749 import grants
from .util import (
    is_openid_scope,
    validate_nonce,
    validate_request_prompt,
    generate_id_token,
)

log = logging.getLogger(__name__)


class OpenIDCode(object):
    def __init__(self, key, alg, iss, exp,
                 exists_nonce, required_nonce=False):
        self.key = key
        self.alg = alg
        self.iss = iss
        self.exp = exp
        self.exists_nonce = exists_nonce
        self.required_nonce = required_nonce

    def process_token(self, grant, token):
        scope = token.get('scope')
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            return token

        request = grant.request
        credential = request.credential
        id_token = generate_id_token(
            key=self.key, token=token, request=request,
            alg=self.alg, iss=self.iss, exp=self.exp,
            nonce=credential.get_nonce(),
            auth_time=credential.get_auth_time(),
        )
        token['id_token'] = id_token
        return token

    def validate_openid_authorization_request(self, grant):
        validate_nonce(grant.request, self.exists_nonce, self.required_nonce)

    def __call__(self, grant):
        grant.register_hook('process_token', self.process_token)
        if is_openid_scope(grant.request.scope):
            grant.register_hook(
                'after_validate_authorization_request',
                self.validate_openid_authorization_request
            )
            grant.register_hook(
                'after_validate_consent_request',
                validate_request_prompt
            )


class OpenIDCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, *args, **kwargs):
        super(OpenIDCodeGrant, self).__init__(*args, **kwargs)
        config = self.server.config
        extension = OpenIDCode(
            key=config['jwt_key'],
            alg=config['jwt_alg'],
            iss=config['jwt_iss'],
            exp=config['jwt_exp'],
            exists_nonce=self.exists_nonce,
        )
        extension(self)

    def exists_nonce(self, nonce, request):  # pragma: no cover
        return self.server.execute_hook('exists_nonce', nonce, request)
