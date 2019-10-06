from django.conf import settings
from .._client import OAuth
from .remote_app import DjangoRemoteApp

__all__ = ['DjangoOAuth']


class DjangoOAuth(OAuth):
    remote_app_class = DjangoRemoteApp

    def load_config(self, name, params):
        return _get_conf(name)


def _get_conf(name):
    config = getattr(settings, 'AUTHLIB_OAUTH_CLIENTS', None)
    if config:
        return config.get(name)
