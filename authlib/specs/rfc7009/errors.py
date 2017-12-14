"""
    authlib.rfc7009.errors
    ~~~~~~~~~~~~~~~~~~~~~~

    OAuth Extensions Error Registration. When a request fails,
    the resource server responds using the appropriate HTTP
    status code and includes one of the following error codes
    in the response.

    https://tools.ietf.org/html/rfc7009#section-2.2.1

    :copyright: (c) 2017 by Hsiaoming Yang.
"""
# flake8: noqa

from ..rfc6749.errors import OAuth2Error
from ..rfc6749.errors import (
    InvalidRequestError,
    InvalidClientError
)


class UnsupportedTokenTypeError(OAuth2Error):
    error = 'unsupported_token_type'
