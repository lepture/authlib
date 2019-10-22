from .._client import OAuth as _OAuth
from ..httpx_client import AsyncOAuth1Client, AsyncOAuth2Client

__all__ = ['OAuth']


class OAuth(_OAuth):
    AVAILABLE_CLIENTS = {
        'httpx': (AsyncOAuth1Client, AsyncOAuth2Client)
    }

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super(OAuth, self).__init__(fetch_token, update_token)

        self.cache = cache
        self.config = config

    def use_oauth_clients(self, name='httpx'):
        clients = self.AVAILABLE_CLIENTS[name]
        self.oauth1_client_cls = clients[0]
        self.oauth2_client_cls = clients[1]

    def load_config(self, name, params):
        if not self.config:
            return {}

        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = self.config.get(conf_key, default=None)
            if v is not None:
                rv[k] = v

        return rv
