"""
    authlib.oauth2.rfc8628
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents an implementation of
    OAuth 2.0 Device Authorization Grant.

    https://tools.ietf.org/html/rfc8628
"""

from .endpoint import DeviceAuthorizationEndpoint
from .device_code import DeviceCodeGrant, DEVICE_CODE_GRANT_TYPE
from .models import DeviceCredentialMixin, DeviceCredentialDict
from .errors import AuthorizationPendingError, SlowDownError, ExpiredTokenError


__all__ = [
    'DeviceAuthorizationEndpoint',
    'DeviceCodeGrant', 'DEVICE_CODE_GRANT_TYPE',
    'DeviceCredentialMixin', 'DeviceCredentialDict',
    'AuthorizationPendingError', 'SlowDownError', 'ExpiredTokenError',
]
