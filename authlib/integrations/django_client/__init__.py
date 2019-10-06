# flake8: noqa

from .oauth_registry import DjangoOAuth
from .remote_app import DjangoRemoteApp, token_update

OAuth = DjangoOAuth
RemoteApp = DjangoRemoteApp

__all__ = [
    'OAuth', 'DjangoOAuth',
    'RemoteApp', 'DjangoRemoteApp',
    'token_update'
]
