# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7636
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    Proof Key for Code Exchange by OAuth Public Clients.

    https://tools.ietf.org/html/rfc7636
"""

from .grant import AuthorizationCodeGrant, create_s256_code_challenge
