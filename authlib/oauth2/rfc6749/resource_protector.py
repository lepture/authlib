"""
    authlib.oauth2.rfc6749.resource_protector
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""

from .errors import MissingAuthorizationError, UnsupportedTokenTypeError


class TokenValidator(object):
    """Base token validator class. Subclass this validator to register
    into ResourceProtector instance.
    """
    TOKEN_TYPE = 'bearer'

    def __init__(self, realm=None, **extra_attributes):
        self.realm = realm
        self.extra_attributes = extra_attributes

    def __call__(self, token_string, scopes, request):
        raise NotImplementedError()


class ResourceProtector(object):
    def __init__(self):
        self._token_validators = {}
        self._default_realm = None
        self._default_auth_type = None

    def register_token_validator(self, validator: TokenValidator):
        if not self._default_auth_type:
            self._default_realm = validator.realm
            self._default_auth_type = validator.TOKEN_TYPE

        if validator.TOKEN_TYPE not in self._token_validators:
            self._token_validators[validator.TOKEN_TYPE] = validator

    def validate_request(self, scopes, request):
        auth = request.headers.get('Authorization')
        if not auth:
            raise MissingAuthorizationError(self._default_auth_type, self._default_realm)

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)

        token_type, token_string = token_parts

        validator = self._token_validators.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)

        return validator(token_string, scopes, request)
