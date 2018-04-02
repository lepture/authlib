"""
    authlib.rfc6750.validator
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Validate Bearer Token for in request, scope and token.
"""

import time
from ..rfc6749.util import scope_to_list
from .errors import (
    InvalidRequestError,
    InvalidTokenError,
    InsufficientScopeError
)


class BearerTokenValidator(object):
    TOKEN_TYPE = 'bearer'

    def __init__(self, realm=None):
        self.realm = realm

    def authenticate_token(self, token_string):
        """
        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    def request_invalid(self, request):
        raise NotImplementedError()

    def token_revoked(self, token):
        raise NotImplementedError()

    def token_expired(self, token):
        expires_at = token.get_expires_at()
        return expires_at < time.time()

    def scope_insufficient(self, token, scope):
        if not scope:
            return False
        token_scopes = set(scope_to_list(token.get_scope()))
        resource_scopes = set(scope_to_list(scope))
        return not token_scopes.issuperset(resource_scopes)

    def __call__(self, token_string, scope, request):
        token = self.authenticate_token(token_string)
        if not token:
            raise InvalidTokenError(realm=self.realm)
        if self.request_invalid(request):
            raise InvalidRequestError()
        if self.token_expired(token):
            raise InvalidTokenError(realm=self.realm)
        if self.token_revoked(token):
            raise InvalidTokenError(realm=self.realm)
        if self.scope_insufficient(token, scope):
            raise InsufficientScopeError()
        return token
