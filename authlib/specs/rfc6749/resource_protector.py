"""
    authlib.specs.rfc6749.resource_protector
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""

from .errors import MissingAuthorizationError, UnsupportedTokenTypeError


class ResourceProtector(object):
    TOKEN_VALIDATORS = {}

    @classmethod
    def register_token_validator(cls, validator):
        if validator.TOKEN_TYPE not in cls.TOKEN_VALIDATORS:
            cls.TOKEN_VALIDATORS[validator.TOKEN_TYPE] = validator

    def validate_request(self, scope, request):
        auth = request.headers.get('Authorization')
        if not auth:
            raise MissingAuthorizationError()

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_type, token_string = auth.split(None, 1)

        validator = self.TOKEN_VALIDATORS.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError()

        return validator(token_string, scope, request)
