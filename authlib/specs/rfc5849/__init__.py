# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc5849
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of The OAuth 1.0 Protocol.

    https://tools.ietf.org/html/rfc5849
"""

# flake8: noqa

from .errors import *
from .wrapper import OAuth1Request
from .signature import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_TYPE_HEADER,
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY,
)

from .client import Client
from .models import (
    ClientMixin,
    TemporaryCredentialMixin,
    TokenCredentialMixin
)
from .authorization_server import AuthorizationServer
from .resource_protector import ResourceProtector
