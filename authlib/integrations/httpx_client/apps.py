import time
import httpx
from ..base_client import BaseApp, OAuth1Mixin, OAuth2Mixin, OpenIDMixin
from ..base_client.async_app import AsyncOAuth1Mixin, AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from .oauth1_client import OAuth1Client, AsyncOAuth1Client
from .oauth2_client import OAuth2Client, AsyncOAuth2Client

__all__ = ['OAuth1App', 'OAuth2App', 'AsyncOAuth1App', 'AsyncOAuth2App']


class OAuth1App(OAuth1Mixin, BaseApp):
    client_cls = OAuth1Client


class AsyncOAuth1App(AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client


class OAuth2App(OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Client

    def load_server_metadata(self):
        if self._server_metadata_url and '_loaded_at' not in self.server_metadata:
            with httpx.Client(**self.client_kwargs) as client:
                resp = client.get(self._server_metadata_url)
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

        with httpx.Client(**self.client_kwargs) as client:
            resp = client.get(uri)
            jwk_set = resp.json()

        self.server_metadata['jwks'] = jwk_set
        return jwk_set


class AsyncOAuth2App(AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp):
    client_cls = AsyncOAuth2Client

    async def load_server_metadata(self):
        if self._server_metadata_url and '_loaded_at' not in self.server_metadata:
            async with httpx.AsyncClient(**self.client_kwargs) as client:
                resp = await client.get(self._server_metadata_url)
                metadata = resp.json()
                metadata['_loaded_at'] = time.time()
            self.server_metadata.update(metadata)
        return self.server_metadata

    async def fetch_jwk_set(self, force=False):
        metadata = await self.load_server_metadata()
        jwk_set = metadata.get('jwks')
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get('jwks_uri')
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        async with httpx.AsyncClient(**self.client_kwargs) as client:
            resp = await client.get(uri)
            jwk_set = resp.json()

        self.server_metadata['jwks'] = jwk_set
        return jwk_set
