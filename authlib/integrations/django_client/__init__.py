# flake8: noqa

from .integration import DjangoIntegration, token_update
from .apps import DjangoOAuth1App, DjangoOAuth2App
from ..base_client import BaseOAuth, OAuthError


class OAuth(BaseOAuth):
    oauth1_client_cls = DjangoOAuth1App
    oauth2_client_cls = DjangoOAuth2App
    framework_integration_cls = DjangoIntegration


__all__ = [
    'OAuth',
    'DjangoOAuth1App', 'DjangoOAuth2App',
    'DjangoIntegration',
    'token_update', 'OAuthError',
]
