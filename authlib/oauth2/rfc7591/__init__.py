"""
    authlib.oauth2.rfc7591
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    OAuth 2.0 Dynamic Client Registration Protocol.

    https://tools.ietf.org/html/rfc7591
"""


from .claims import ClientMetadataClaims
from .endpoint import ClientRegistrationEndpoint
from .errors import (
    InvalidRedirectURIError,
    InvalidClientMetadataError,
    InvalidSoftwareStatementError,
    UnapprovedSoftwareStatementError,
)

__all__ = [
    'ClientMetadataClaims', 'ClientRegistrationEndpoint',
    'InvalidRedirectURIError', 'InvalidClientMetadataError',
    'InvalidSoftwareStatementError', 'UnapprovedSoftwareStatementError',
]
