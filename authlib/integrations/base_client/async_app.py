import time
import logging
from authlib.common.urls import urlparse
from authlib.jose import JsonWebToken
from authlib.oidc.core import UserInfo, CodeIDToken, ImplicitIDToken
from .base_app import BaseApp
from .errors import (
    MissingRequestTokenError,
    MissingTokenError,
)

__all__ = ['AsyncRemoteApp']

log = logging.getLogger(__name__)


class AsyncRemoteApp(BaseApp):
    async def load_server_metadata(self):
        if self._server_metadata_url and '_loaded_at' not in self.server_metadata:
            metadata = await self._fetch_server_metadata(self._server_metadata_url)
            metadata['_loaded_at'] = time.time()
            self.server_metadata.update(metadata)
        return self.server_metadata

    async def _on_update_token(self, token, refresh_token=None, access_token=None):
        if self._update_token:
            await self._update_token(
                token,
                refresh_token=refresh_token,
                access_token=access_token,
            )

    async def _create_oauth1_authorization_url(self, client, authorization_endpoint, **kwargs):
        params = {}
        if self.request_token_params:
            params.update(self.request_token_params)
        token = await client.fetch_request_token(
            self.request_token_url, **params
        )
        log.debug('Fetch request token: {!r}'.format(token))
        url = client.create_authorization_url(authorization_endpoint, **kwargs)
        return {'url': url, 'request_token': token}

    async def create_authorization_url(self, redirect_uri=None, **kwargs):
        """Generate the authorization url and state for HTTP redirect.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: dict
        """
        metadata = await self.load_server_metadata()
        authorization_endpoint = self.authorize_url
        if not authorization_endpoint and not self.request_token_url:
            authorization_endpoint = metadata.get('authorization_endpoint')

        if not authorization_endpoint:
            raise RuntimeError('Missing "authorize_url" value')

        if self.authorize_params:
            kwargs.update(self.authorize_params)

        async with self._get_oauth_client(**metadata) as client:
            client.redirect_uri = redirect_uri

            if self.request_token_url:
                return await self._create_oauth1_authorization_url(
                    client, authorization_endpoint, **kwargs)
            else:
                return self._create_oauth2_authorization_url(
                    client, authorization_endpoint, **kwargs)

    async def fetch_access_token(self, redirect_uri=None, request_token=None, **params):
        """Fetch access token in one step.

        :param redirect_uri: Callback or Redirect URI that is used in
                             previous :meth:`authorize_redirect`.
        :param request_token: A previous request token for OAuth 1.
        :param params: Extra parameters to fetch access token.
        :return: A token dict.
        """
        metadata = await self.load_server_metadata()
        token_endpoint = self.access_token_url
        if not token_endpoint and not self.request_token_url:
            token_endpoint = metadata.get('token_endpoint')

        async with self._get_oauth_client(**metadata) as client:
            if self.request_token_url:
                client.redirect_uri = redirect_uri
                if request_token is None:
                    raise MissingRequestTokenError()
                # merge request token with verifier
                token = {}
                token.update(request_token)
                token.update(params)
                client.token = token
                kwargs = self.access_token_params or {}
                token = await client.fetch_access_token(token_endpoint, **kwargs)
                client.redirect_uri = None
            else:
                client.redirect_uri = redirect_uri
                kwargs = {}
                if self.access_token_params:
                    kwargs.update(self.access_token_params)
                kwargs.update(params)
                token = await client.fetch_token(token_endpoint, **kwargs)
            return token

    async def request(self, method, url, token=None, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)

        withhold_token = kwargs.get('withhold_token')
        if token and not withhold_token:
            metadata = await self.load_server_metadata()
        else:
            metadata = {}

        async with self._get_oauth_client(**metadata) as client:
            request = kwargs.pop('request', None)

            if withhold_token:
                return await client.request(method, url, **kwargs)

            if token is None and request:
                token = await self._fetch_token(request)

            if token is None:
                raise MissingTokenError()

            client.token = token
            return await client.request(method, url, **kwargs)

    async def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        metadata = await self.load_server_metadata()
        resp = await self.get(metadata['userinfo_endpoint'], **kwargs)
        data = resp.json()

        compliance_fix = metadata.get('userinfo_compliance_fix')
        if compliance_fix:
            data = await compliance_fix(self, data)
        return UserInfo(data)

    async def _parse_id_token(self, token, nonce, claims_options=None):
        """Return an instance of UserInfo from token's ``id_token``."""
        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )
        if 'access_token' in token:
            claims_params['access_token'] = token['access_token']
            claims_cls = CodeIDToken
        else:
            claims_cls = ImplicitIDToken

        metadata = await self.load_server_metadata()
        if claims_options is None and 'issuer' in metadata:
            claims_options = {'iss': {'values': [metadata['issuer']]}}

        alg_values = metadata.get('id_token_signing_alg_values_supported')
        if not alg_values:
            alg_values = ['RS256']

        jwt = JsonWebToken(alg_values)

        jwk_set = await self._fetch_jwk_set()
        try:
            claims = jwt.decode(
                token['id_token'], key=jwk_set,
                claims_cls=claims_cls,
                claims_options=claims_options,
                claims_params=claims_params,
            )
        except ValueError:
            jwk_set = await self._fetch_jwk_set(force=True)
            claims = jwt.decode(
                token['id_token'], key=jwk_set,
                claims_cls=claims_cls,
                claims_options=claims_options,
                claims_params=claims_params,
            )

        claims.validate(leeway=120)
        return UserInfo(claims)

    async def _fetch_jwk_set(self, force=False):
        metadata = await self.load_server_metadata()
        jwk_set = metadata.get('jwks')
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get('jwks_uri')
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = await self._fetch_server_metadata(uri)
        self.server_metadata['jwks'] = jwk_set
        return jwk_set

    async def _fetch_server_metadata(self, url):
        async with self._get_oauth_client() as client:
            resp = await client.request('GET', url, withhold_token=True)
            return resp.json()
