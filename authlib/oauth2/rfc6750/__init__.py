# -*- coding: utf-8 -*-
"""
    authlib.oauth2.rfc6750
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    The OAuth 2.0 Authorization Framework: Bearer Token Usage.

    https://tools.ietf.org/html/rfc6750
"""

from .errors import InvalidRequestError, InvalidTokenError, InsufficientScopeError
from .parameters import add_bearer_token
from .wrappers import BearerToken
from .validator import BearerTokenValidator


__all__ = [
    'InvalidRequestError', 'InvalidTokenError', 'InsufficientScopeError',
    'add_bearer_token',
    'BearerToken',
    'BearerTokenValidator',
]
