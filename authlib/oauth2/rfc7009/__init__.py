# -*- coding: utf-8 -*-
"""
    authlib.oauth2.rfc7009
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    OAuth 2.0 Token Revocation.

    https://tools.ietf.org/html/rfc7009
"""

# flake8: noqa

from .parameters import prepare_revoke_token_request
from .revocation import RevocationEndpoint
