# flake8: noqa

from ..base_client import BaseOAuth, OAuthError
from .integration import StartletteIntegration, StarletteRemoteApp


class OAuth(BaseOAuth):
    framework_client_cls = StarletteRemoteApp
    framework_integration_cls = StartletteIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super(OAuth, self).__init__(fetch_token, update_token)
        self.cache = cache
        self.config = config


__all__ = [
    'OAuth', 'StartletteIntegration', 'StarletteRemoteApp',
    'OAuthError',
]
