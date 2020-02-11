# flake8: noqa

from .integration import DjangoIntegration, DjangoRemoteApp, token_update
from ..base_client import BaseOAuth, OAuthError


class OAuth(BaseOAuth):
    framework_integration_cls = DjangoIntegration
    framework_client_cls = DjangoRemoteApp


__all__ = [
    'OAuth', 'DjangoRemoteApp', 'DjangoIntegration',
    'token_update', 'OAuthError',
]
