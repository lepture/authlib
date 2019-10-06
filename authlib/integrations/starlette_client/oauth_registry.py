from .remote_app import RemoteApp
from .._client import OAuth as _OAuth

__all__ = ['OAuth']


class OAuth(_OAuth):
    remote_app_class = RemoteApp

    def load_config(self, name, params):
        # TODO: framework configuration
        return {}
