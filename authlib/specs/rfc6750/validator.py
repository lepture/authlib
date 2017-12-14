"""
    authlib.rfc6750.validator
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Validate Bearer Token for in request, scope and token.

    :copyright: (c) 2017 by Hsiaoming Yang.
"""

import time
from ..rfc6749.util import get_obj_value, scope_to_list
from .errors import (
    InvalidRequestError,
    InvalidTokenError,
    InsufficientScopeError
)


class BearerTokenValidator(object):
    def __init__(self, realm=None):
        self.realm = realm

    def request_invalid(self, method, uri, body, headers):
        raise NotImplementedError()

    def token_revoked(self, token):
        raise NotImplementedError()

    def token_expired(self, token):
        expires_at = get_obj_value(token, 'expires_at')
        return expires_at < time.time()

    def scope_insufficient(self, token, scope):
        if not scope:
            return False
        token_scopes = set(scope_to_list(get_obj_value(token, 'scope')))
        resource_scopes = set(scope_to_list(scope))
        return not token_scopes.issuperset(resource_scopes)

    def __call__(self, token, scope, method, uri, body, headers):
        if not token:
            raise InvalidTokenError(realm=self.realm)
        if self.request_invalid(method, uri, body, headers):
            raise InvalidRequestError()
        if self.token_expired(token):
            raise InvalidTokenError(realm=self.realm)
        if self.token_revoked(token):
            raise InvalidTokenError(realm=self.realm)
        if self.scope_insufficient(token, scope):
            raise InsufficientScopeError()
