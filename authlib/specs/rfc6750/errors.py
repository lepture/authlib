"""
    authlib.rfc6750.errors
    ~~~~~~~~~~~~~~~~~~~~~~

    OAuth Extensions Error Registration. When a request fails,
    the resource server responds using the appropriate HTTP
    status code and includes one of the following error codes
    in the response.

    https://tools.ietf.org/html/rfc6750#section-6.2

    :copyright: (c) 2017 by Hsiaoming Yang.
"""
from ..rfc6749.errors import OAuth2Error

__all__ = [
    'InvalidRequestError',
    'InvalidTokenError',
    'ExpiredTokenError',
    'RevokedTokenError',
    'MalformedTokenError',
    'InsufficientScopeError'
]


class InvalidRequestError(OAuth2Error):
    """The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats the same
    parameter, uses more than one method for including an access
    token, or is otherwise malformed.  The resource server SHOULD
    respond with the HTTP 400 (Bad Request) status code.

    https://tools.ietf.org/html/rfc6750#section-3.1
    """
    error = 'invalid_request'
    status_code = 400


class InvalidTokenError(OAuth2Error):
    """The access token provided is expired, revoked, malformed, or
    invalid for other reasons. The resource SHOULD respond with
    the HTTP 401 (Unauthorized) status code.  The client MAY
    request a new access token and retry the protected resource
    request.

    https://tools.ietf.org/html/rfc6750#section-3.1
    """
    error = 'invalid_token'
    status_code = 401
    description = (
        'The access token provided is expired, revoked, malformed, '
        'or invalid for other reasons.'
    )

    def get_headers(self):
        """If the protected resource request does not include authentication
        credentials or does not contain an access token that enables access
        to the protected resource, the resource server MUST include the HTTP
        "WWW-Authenticate" response header field; it MAY include it in
        response to other conditions as well.

        https://tools.ietf.org/html/rfc6750#section-3
        """
        headers = super(InvalidTokenError, self).get_headers()

        extras = []
        if self.realm:
            extras.append('realm="{}"'.format(self.realm))
        extras.append('error="{}"'.format(self.error))
        extras.append('error_description="{}"'.format(self.description))
        headers.append(
            ('WWW-Authenticate', 'Bearer ' + ', '.join(extras))
        )
        return headers


class ExpiredTokenError(InvalidTokenError):
    description = 'The access token provided is expired'


class RevokedTokenError(InvalidTokenError):
    description = 'The access token provided is revoked'


class MalformedTokenError(InvalidTokenError):
    description = 'The access token provided is malformed'


class InsufficientScopeError(OAuth2Error):
    """The request requires higher privileges than provided by the
    access token. The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the protected
    resource.

    https://tools.ietf.org/html/rfc6750#section-3.1
    """
    error = 'insufficient_scope'
    status_code = 403
    description = (
        'The request requires higher privileges than '
        'provided by the access token.'
    )
