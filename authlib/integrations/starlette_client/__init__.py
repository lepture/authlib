# flake8: noqa

from ..base_client import BaseOAuth, OAuthError
from .integration import StarletteIntegration
from .apps import StarletteOAuth1App, StarletteOAuth2App


class OAuth(BaseOAuth):
    oauth1_client_cls = StarletteOAuth1App
    oauth2_client_cls = StarletteOAuth2App
    framework_integration_cls = StarletteIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super().__init__(
            cache=cache, fetch_token=fetch_token, update_token=update_token)
        self.config = config


__all__ = [
    'OAuth', 'OAuthError',
    'StarletteIntegration', 'StarletteOAuth1App', 'StarletteOAuth2App',
]
