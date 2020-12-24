import time
import requests
from ..base_client import BaseApp, OAuth1Mixin, OAuth2Mixin, OpenIDMixin
from .oauth1_session import OAuth1Session
from .oauth2_session import OAuth2Session

__all__ = ['OAuth1App', 'OAuth2App']


class OAuth1App(OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session


class OAuth2App(OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    def load_server_metadata(self):
        if self._server_metadata_url and '_loaded_at' not in self.server_metadata:
            resp = requests.get(self._server_metadata_url)
            metadata = resp.json()
            metadata['_loaded_at'] = time.time()
            self.server_metadata.update(metadata)
        return self.server_metadata

    def fetch_jwk_set(self, force=False):
        metadata = self.load_server_metadata()
        jwk_set = metadata.get('jwks')
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get('jwks_uri')
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        resp = requests.get(uri)
        self.server_metadata['jwks'] = resp.json()
        return jwk_set
