"""
    authlib.rfc6750.validator
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Validate Bearer Token for in request, scope and token.

    :copyright: (c) 2017 by Hsiaoming Yang.
"""

from .errors import (
    InvalidRequestError,
    ExpiredTokenError,
    RevokedTokenError,
    MalformedTokenError,
    InsufficientScopeError
)


class BearerTokenValidator(object):
    def __init__(self, realm=None):
        self.realm = realm

    def request_invalid(self, token, scope, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def token_expired(self, token, scope, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def token_revoked(self, token, scope, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def token_malformed(self, token, scope, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def scope_insufficient(self, token, scope, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def __call__(self, token, scope, request):
        if self.request_invalid(token, scope, request):
            raise InvalidRequestError()
        if self.token_expired(token, scope, request):
            raise ExpiredTokenError(realm=self.realm)
        if self.token_revoked(token, scope, request):
            raise RevokedTokenError(realm=self.realm)
        if self.token_malformed(token, scope, request):
            raise MalformedTokenError(realm=self.realm)
        if self.scope_insufficient(token, scope, request):
            raise InsufficientScopeError()
