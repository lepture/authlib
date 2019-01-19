# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc5849
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of The OAuth 1.0 Protocol.

    https://tools.ietf.org/html/rfc5849
"""

# flake8: noqa

from authlib.oauth1.rfc5849.errors import *
from authlib.oauth1 import (
    ClientAuth as Client,
    OAuth1Request,
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_TYPE_HEADER,
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY,

    ClientMixin,
    TemporaryCredentialMixin,
    TokenCredentialMixin,
    TemporaryCredential,

    AuthorizationServer,
    ResourceProtector,
)
