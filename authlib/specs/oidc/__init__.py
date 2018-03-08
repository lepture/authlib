"""
    authlib.specs.oidc
    ~~~~~~~~~~~~~~~~~~

    OpenID Connect Core 1.0 Implementation.

    http://openid.net/specs/openid-connect-core-1_0.html
"""
# flake8: noqa

from .legacy import parse_id_token, verify_id_token
from .claims import IDToken, CodeIDToken, ImplicitIDToken, HybridIDToken
from .claims import get_claim_cls_by_response_type
from .models import AuthorizationCodeMixin
