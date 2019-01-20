"""
    authlib.oauth1.rfc5849
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of The OAuth 1.0 Protocol.

    https://tools.ietf.org/html/rfc5849
"""

from .wrapper import OAuth1Request
from .client_auth import ClientAuth
from .signature import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_TYPE_HEADER,
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY,
)
from .models import (
    ClientMixin,
    TemporaryCredentialMixin,
    TokenCredentialMixin,
    TemporaryCredential,
)
from .authorization_server import AuthorizationServer
from .resource_protector import ResourceProtector

__all__ = [
    'OAuth1Request',
    'ClientAuth',
    'SIGNATURE_HMAC_SHA1',
    'SIGNATURE_RSA_SHA1',
    'SIGNATURE_PLAINTEXT',
    'SIGNATURE_TYPE_HEADER',
    'SIGNATURE_TYPE_QUERY',
    'SIGNATURE_TYPE_BODY',

    'ClientMixin',
    'TemporaryCredentialMixin',
    'TokenCredentialMixin',
    'TemporaryCredential',
    'AuthorizationServer',
    'ResourceProtector',
]
