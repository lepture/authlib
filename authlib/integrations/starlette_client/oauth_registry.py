from .remote_app import RemoteApp
from .._client import OAuth as _OAuth
from ..httpx_client import AsyncOAuth1Client, AsyncOAuth2Client

__all__ = ['OAuth']


class OAuth(_OAuth):
    remote_app_class = RemoteApp
    AVAILABLE_CLIENTS = {
        'httpx': (AsyncOAuth1Client, AsyncOAuth2Client)
    }

    def use_oauth_clients(self, name='httpx'):
        clients = self.AVAILABLE_CLIENTS[name]
        self.oauth1_client_cls = clients[0]
        self.oauth2_client_cls = clients[1]

    def load_config(self, name, params):
        # TODO: framework configuration
        return {}
