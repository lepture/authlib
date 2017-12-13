"""
    authlib.specs.rfc6749.grants
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation for `Section 4`_ of "Obtaining Authorization".

    To request an access token, the client obtains authorization from the
    resource owner. The authorization is expressed in the form of an
    authorization grant, which the client uses to request the access
    token. OAuth defines four grant types: authorization code, implicit,
    resource owner password credentials, and client credentials. It also
    provides an extension mechanism for defining additional grant types.

    .. _`Section 4`: http://tools.ietf.org/html/rfc6749#section-4

    :copyright: (c) 2017 by Hsiaoming Yang.
    :license: LGPLv3, see LICENSE for more details.
"""

# flake8: noqa

from .base import BaseGrant
from .authorization_code import AuthorizationCodeGrant
from .implicit import ImplicitGrant
from .resource_owner_password_credentials import ResourceOwnerPasswordCredentialsGrant
from .client_credentials import ClientCredentialsGrant
from .refresh_token import RefreshTokenGrant
