from .._client import OAuth
from .remote_app import StarletteRemoteApp

__all__ = ['StarletteOAuth']


class StarletteOAuth(OAuth):
    remote_app_class = StarletteRemoteApp

    def load_config(self, name, params):
        # TODO: framework configuration
        return {}
