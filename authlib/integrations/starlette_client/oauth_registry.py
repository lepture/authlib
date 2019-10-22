from .remote_app import RemoteApp
from ..asgi_client import OAuth as _OAuth

__all__ = ['OAuth']


class OAuth(_OAuth):
    remote_app_class = RemoteApp
