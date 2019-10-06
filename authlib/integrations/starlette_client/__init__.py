# flake8: noqa

from .oauth_registry import StarletteOAuth
from .remote_app import StarletteRemoteApp

OAuth = StarletteOAuth
RemoteApp = StarletteRemoteApp

__all__ = [
    'OAuth', 'StarletteOAuth',
    'RemoteApp', 'StarletteRemoteApp',
]
