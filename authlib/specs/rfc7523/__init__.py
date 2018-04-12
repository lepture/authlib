# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7523
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Token (JWT) Profile for OAuth 2.0 Client
    Authentication and Authorization Grants.

    https://tools.ietf.org/html/rfc7523
"""

from .parameters import sign_jwt_bearer_assertion
from .consts import JWT_BEARER_GRANT_TYPE, JWT_BEARER_CLIENT_ASSERTION_TYPE
