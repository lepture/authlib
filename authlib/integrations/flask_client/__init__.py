# flake8: noqa

from .oauth_registry import FlaskOAuth
from .remote_app import FlaskRemoteApp, token_update

OAuth = FlaskOAuth
RemoteApp = FlaskRemoteApp

__all__ = [
    'OAuth', 'FlaskOAuth',
    'RemoteApp', 'FlaskRemoteApp',
    'token_update',
]
