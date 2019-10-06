from django.conf import settings
from .remote_app import RemoteApp
from .._client import OAuth as _OAuth

__all__ = ['OAuth']


class OAuth(_OAuth):
    remote_app_class = RemoteApp

    def load_config(self, name, params):
        return _get_conf(name)


def _get_conf(name):
    config = getattr(settings, 'AUTHLIB_OAUTH_CLIENTS', None)
    if config:
        return config.get(name)
