"""
    authlib.specs.oidc
    ~~~~~~~~~~~~~~~~~~

    OpenID Connect Core 1.0 Implementation.

    http://openid.net/specs/openid-connect-core-1_0.html
"""
# flake8: noqa

from .id_token import (
    IDToken, IDTokenError,
    CodeIDToken, ImplicitIDToken, HybridIDToken,
    parse_id_token, validate_id_token, verify_id_token,
)
