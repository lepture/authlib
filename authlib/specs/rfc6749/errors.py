"""
    authlib.specs.rfc6749.errors
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation for OAuth 2 Error Response. A basic error has
    parameters:

    error
         REQUIRED.  A single ASCII [USASCII] error code.

    error_description
         OPTIONAL.  Human-readable ASCII [USASCII] text providing
         additional information, used to assist the client developer in
         understanding the error that occurred.

    error_uri
         OPTIONAL.  A URI identifying a human-readable web page with
         information about the error, used to provide the client
         developer with additional information about the error.
         Values for the "error_uri" parameter MUST conform to the
         URI-reference syntax and thus MUST NOT include characters
         outside the set %x21 / %x23-5B / %x5D-7E.

    state
         REQUIRED if a "state" parameter was present in the client
         authorization request.  The exact value received from the
         client.

    https://tools.ietf.org/html/rfc6749#section-5.2
"""

from authlib.common.security import is_secure_transport


class OAuth2Error(Exception):
    error = None
    status_code = 400
    description = ''

    def __init__(self, description=None, status_code=None,
                 uri=None, state=None):
        if description is not None:
            self.description = description

        message = '%s: %s' % (self.error, self.description)
        super(OAuth2Error, self).__init__(message)

        if status_code is not None:
            self.status_code = status_code

        self.uri = uri
        self.state = state

    def __str__(self):
        return '{} {}: {}'.format(
            self.status_code,
            self.error,
            self.description
        )

    def __repr__(self):
        return "<{} '{}: {}'>".format(
            self.__class__.__name__,
            self.status_code,
            self.error
        )

    def get_body(self):
        """Get a list of body."""
        error = [('error', self.error)]
        if self.description:
            error.append(('error_description', self.description))
        if self.uri:
            error.append(('error_uri', self.uri))
        if self.state:
            error.append(('state', self.state))
        return error

    def get_headers(self):
        """Get a list of headers."""
        return [
            ('Content-Type', 'application/json'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache')
        ]


class InsecureTransportError(OAuth2Error):
    error = 'insecure_transport'
    description = 'OAuth 2 MUST utilize https.'

    @classmethod
    def check(cls, uri):
        if not is_secure_transport(uri):
            raise cls()


class InvalidRequestError(OAuth2Error):
    """The request is missing a required parameter, includes an
    unsupported parameter value (other than grant type),
    repeats a parameter, includes multiple credentials,
    utilizes more than one mechanism for authenticating the
    client, or is otherwise malformed.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_request'


class InvalidClientError(OAuth2Error):
    """Client authentication failed (e.g., unknown client, no
    client authentication included, or unsupported
    authentication method).  The authorization server MAY
    return an HTTP 401 (Unauthorized) status code to indicate
    which HTTP authentication schemes are supported.  If the
    client attempted to authenticate via the "Authorization"
    request header field, the authorization server MUST
    respond with an HTTP 401 (Unauthorized) status code and
    include the "WWW-Authenticate" response header field
    matching the authentication scheme used by the client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_client'
    status_code = 401


class InvalidGrantError(OAuth2Error):
    """The provided authorization grant (e.g., authorization
    code, resource owner credentials) or refresh token is
    invalid, expired, revoked, does not match the redirection
    URI used in the authorization request, or was issued to
    another client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_grant'


class UnauthorizedClientError(OAuth2Error):
    """ The authenticated client is not authorized to use this
    authorization grant type.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'unauthorized_client'


class UnsupportedGrantTypeError(OAuth2Error):
    """The authorization grant type is not supported by the
    authorization server.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'unsupported_grant_type'


class InvalidScopeError(OAuth2Error):
    """The requested scope is invalid, unknown, malformed, or
    exceeds the scope granted by the resource owner.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_scope'
    description = 'The requested scope is invalid, unknown, or malformed.'


class AccessDeniedError(OAuth2Error):
    """The resource owner or authorization server denied the request.

    Used in authorization endpoint for "code" and "implicit". Defined in
    `Section 4.1.2.1`_.

    .. _`Section 4.1.2.1`: https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    """
    error = 'access_denied'
    description = (
        'The resource owner or authorization server denied the request'
    )


# -- below are extended errors -- #


class MissingCodeError(OAuth2Error):
    error = 'missing_code'
    description = 'Missing "code" in response.'


class MissingTokenError(OAuth2Error):
    error = 'missing_token'
    description = 'Missing "access_token" in response.'


class MissingTokenTypeError(OAuth2Error):
    error = 'missing_token_type'
    description = 'Missing "token_type" in response.'


class MismatchingStateError(OAuth2Error):
    error = 'mismatching_state'
    description = 'CSRF Warning! State not equal in request and response.'
