"""
    authlib.oauth2.rfc6749.resource_protector
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""

from .errors import MissingAuthorizationError, UnsupportedTokenTypeError


class ResourceProtector(object):
    def __init__(self):
        self._token_validators = {}

    def register_token_validator(self, validator):
        if validator.TOKEN_TYPE not in self._token_validators:
            self._token_validators[validator.TOKEN_TYPE] = validator

    def validate_request(self, scope, request, scope_operator='AND'):
        auth = request.headers.get('Authorization')
        if not auth:
            raise MissingAuthorizationError()

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError()

        token_type, token_string = token_parts

        validator = self._token_validators.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError()

        return validator(token_string, scope, request, scope_operator)
