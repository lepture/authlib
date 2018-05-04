from requests.compat import is_py3
from authlib.common.errors import AuthlibBaseError


OAuthError = AuthlibBaseError


class MissingRequestTokenError(OAuthError):
    error = 'missing_request_token'


class MissingTokenError(OAuthError):
    error = 'missing_token'


class MissingVerifierError(OAuthError):
    error = 'missing_verifier'
    description = 'No client verifier has been set.'


class FetchTokenDeniedError(OAuthError):
    error = 'fetch_token_denied'


class TokenExpiredError(OAuthError):
    error = 'token_expired'


class UnsupportedTokenTypeError(OAuthError):
    error = 'unsupported_token_type'


class MismatchingStateError(OAuthError):
    error = 'mismatching_state'
    description = 'CSRF Warning! State not equal in request and response.'


class OAuthException(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        if is_py3:
            return self.message
        return self.message.encode('utf-8')

    def __unicode__(self):
        return self.message
