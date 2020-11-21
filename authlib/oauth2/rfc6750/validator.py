"""
    authlib.oauth2.rfc6750.validator
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Validate Bearer Token for in request, scope and token.
"""

from ..rfc6749.util import scope_to_list
from ..rfc6749 import TokenValidator
from .errors import (
    InvalidRequestError,
    InvalidTokenError,
    InsufficientScopeError
)


class BearerTokenValidator(TokenValidator):
    TOKEN_TYPE = 'bearer'

    def authenticate_token(self, token_string):
        """A method to query token from database with the given token string.
        Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    def request_invalid(self, request):
        """Check if the HTTP request is valid or not.  Developers MUST
        re-implement this method.  For instance, your server requires a
        "X-Device-Version" in the header::

            def request_invalid(self, request):
                return 'X-Device-Version' in request.headers

        Usually, you don't have to detect if the request is valid or not,
        you can just return a ``False``.

        :param request: instance of HttpRequest
        :return: Boolean
        """
        raise NotImplementedError()

    def scope_insufficient(self, token, scopes):
        if not scopes:
            return False

        token_scopes = scope_to_list(token.get_scope())
        if not token_scopes:
            return True

        token_scopes = set(token_scopes)
        for scope in scopes:
            resource_scopes = set(scope_to_list(scope))
            if token_scopes.issuperset(resource_scopes):
                return False

        return True

    def __call__(self, token_string, scopes, request):
        if self.request_invalid(request):
            raise InvalidRequestError()
        token = self.authenticate_token(token_string)
        if not token:
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_expired():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_revoked():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if self.scope_insufficient(token, scopes):
            raise InsufficientScopeError()
        return token
