"""
    authlib.specs.oidc
    ~~~~~~~~~~~~~~~~~~

    OpenID Connect Core 1.0 Implementation.

    http://openid.net/specs/openid-connect-core-1_0.html
"""
# flake8: noqa

from .id_token import (
    IDToken, CodeIDToken, ImplicitIDToken, HybridIDToken,
    IDTokenError, parse_id_token
)
