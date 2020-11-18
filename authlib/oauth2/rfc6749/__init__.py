# -*- coding: utf-8 -*-
"""
    authlib.oauth2.rfc6749
    ~~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    The OAuth 2.0 Authorization Framework.

    https://tools.ietf.org/html/rfc6749
"""

from .wrappers import OAuth2Request, OAuth2Token, HttpRequest
from .errors import (
    OAuth2Error,
    AccessDeniedError,
    MissingAuthorizationError,
    InvalidGrantError,
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    InsecureTransportError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
    UnsupportedTokenTypeError,
    # exceptions for clients
    MissingCodeException,
    MissingTokenException,
    MissingTokenTypeException,
    MismatchingStateException,
)
from .models import ClientMixin, AuthorizationCodeMixin, TokenMixin
from .authenticate_client import ClientAuthentication
from .authorization_server import AuthorizationServer
from .resource_protector import ResourceProtector
from .token_endpoint import TokenEndpoint
from .grants import (
    BaseGrant,
    AuthorizationEndpointMixin,
    TokenEndpointMixin,
    AuthorizationCodeGrant,
    ImplicitGrant,
    ResourceOwnerPasswordCredentialsGrant,
    ClientCredentialsGrant,
    RefreshTokenGrant,
)

__all__ = [
    'OAuth2Request', 'OAuth2Token', 'HttpRequest',
    'OAuth2Error',
    'AccessDeniedError',
    'MissingAuthorizationError',
    'InvalidGrantError',
    'InvalidClientError',
    'InvalidRequestError',
    'InvalidScopeError',
    'InsecureTransportError',
    'UnauthorizedClientError',
    'UnsupportedGrantTypeError',
    'UnsupportedTokenTypeError',
    'MissingCodeException',
    'MissingTokenException',
    'MissingTokenTypeException',
    'MismatchingStateException',
    'ClientMixin', 'AuthorizationCodeMixin', 'TokenMixin',
    'ClientAuthentication',
    'AuthorizationServer',
    'ResourceProtector',
    'TokenEndpoint',
    'BaseGrant',
    'AuthorizationEndpointMixin',
    'TokenEndpointMixin',
    'AuthorizationCodeGrant',
    'ImplicitGrant',
    'ResourceOwnerPasswordCredentialsGrant',
    'ClientCredentialsGrant',
    'RefreshTokenGrant',
]
