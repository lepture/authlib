import time
import logging
from authlib.common.urls import urlparse
from authlib.jose import JsonWebToken, JsonWebKey
from authlib.oidc.core import UserInfo, CodeIDToken, ImplicitIDToken
from .base_app import BaseApp
from .errors import (
    MissingRequestTokenError,
    MissingTokenError,
)

__all__ = ['RemoteApp']

log = logging.getLogger(__name__)


class RemoteApp(BaseApp):
    def load_server_metadata(self):
        if self._server_metadata_url and '_loaded_at' not in self.server_metadata:
            metadata = self._fetch_server_metadata(self._server_metadata_url)
            metadata['_loaded_at'] = time.time()
            self.server_metadata.update(metadata)
        return self.server_metadata

    def _on_update_token(self, token, refresh_token=None, access_token=None):
        if callable(self._update_token):
            self._update_token(
                token,
                refresh_token=refresh_token,
                access_token=access_token,
            )
        self.framework.update_token(
            token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    def _create_oauth1_authorization_url(self, client, authorization_endpoint, **kwargs):
        params = {}
        if self.request_token_params:
            params.update(self.request_token_params)
        token = client.fetch_request_token(
            self.request_token_url, **params
        )
        log.debug('Fetch request token: {!r}'.format(token))
        url = client.create_authorization_url(authorization_endpoint, **kwargs)
        return {'url': url, 'request_token': token}

    def create_authorization_url(self, redirect_uri=None, **kwargs):
        """Generate the authorization url and state for HTTP redirect.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: dict
        """
        metadata = self.load_server_metadata()
        authorization_endpoint = self.authorize_url
        if not authorization_endpoint and not self.request_token_url:
            authorization_endpoint = metadata.get('authorization_endpoint')

        if not authorization_endpoint:
            raise RuntimeError('Missing "authorize_url" value')

        if self.authorize_params:
            kwargs.update(self.authorize_params)

        with self._get_oauth_client(**metadata) as client:
            client.redirect_uri = redirect_uri

            if self.request_token_url:
                return self._create_oauth1_authorization_url(
                    client, authorization_endpoint, **kwargs)
            else:
                return self._create_oauth2_authorization_url(
                    client, authorization_endpoint, **kwargs)

    def fetch_access_token(self, redirect_uri=None, request_token=None, **params):
        """Fetch access token in one step.

        :param redirect_uri: Callback or Redirect URI that is used in
                             previous :meth:`authorize_redirect`.
        :param request_token: A previous request token for OAuth 1.
        :param params: Extra parameters to fetch access token.
        :return: A token dict.
        """
        metadata = self.load_server_metadata()
        token_endpoint = self.access_token_url
        if not token_endpoint and not self.request_token_url:
            token_endpoint = metadata.get('token_endpoint')

        with self._get_oauth_client(**metadata) as client:
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
                token = client.fetch_access_token(token_endpoint, **kwargs)
                client.redirect_uri = None
            else:
                client.redirect_uri = redirect_uri
                kwargs = {}
                if self.access_token_params:
                    kwargs.update(self.access_token_params)
                kwargs.update(params)
                token = client.fetch_token(token_endpoint, **kwargs)
            return token

    def request(self, method, url, token=None, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)

        withhold_token = kwargs.get('withhold_token')
        if not withhold_token:
            metadata = self.load_server_metadata()
        else:
            metadata = {}

        with self._get_oauth_client(**metadata) as session:
            request = kwargs.pop('request', None)
            if withhold_token:
                return session.request(method, url, **kwargs)

            if token is None and self._fetch_token and request:
                token = self._fetch_token(request)
            if token is None:
                raise MissingTokenError()

            session.token = token
            return session.request(method, url, **kwargs)

    def fetch_jwk_set(self, force=False):
        metadata = self.load_server_metadata()
        jwk_set = metadata.get('jwks')
        if jwk_set and not force:
            return jwk_set
        uri = metadata.get('jwks_uri')
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        jwk_set = self._fetch_server_metadata(uri)
        self.server_metadata['jwks'] = jwk_set
        return jwk_set

    def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        metadata = self.load_server_metadata()
        resp = self.get(metadata['userinfo_endpoint'], **kwargs)
        data = resp.json()

        compliance_fix = metadata.get('userinfo_compliance_fix')
        if compliance_fix:
            data = compliance_fix(self, data)
        return UserInfo(data)

    def _parse_id_token(self, request, token, claims_options=None, leeway=120):
        """Return an instance of UserInfo from token's ``id_token``."""
        if 'id_token' not in token:
            return None

        def load_key(header, payload):
            jwk_set = JsonWebKey.import_key_set(self.fetch_jwk_set())
            try:
                return jwk_set.find_by_kid(header.get('kid'))
            except ValueError:
                # re-try with new jwk set
                jwk_set = JsonWebKey.import_key_set(self.fetch_jwk_set(force=True))
                return jwk_set.find_by_kid(header.get('kid'))

        nonce = self.framework.get_session_data(request, 'nonce')
        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )
        if 'access_token' in token:
            claims_params['access_token'] = token['access_token']
            claims_cls = CodeIDToken
        else:
            claims_cls = ImplicitIDToken

        metadata = self.load_server_metadata()
        if claims_options is None and 'issuer' in metadata:
            claims_options = {'iss': {'values': [metadata['issuer']]}}

        alg_values = metadata.get('id_token_signing_alg_values_supported')
        if not alg_values:
            alg_values = ['RS256']

        jwt = JsonWebToken(alg_values)
        claims = jwt.decode(
            token['id_token'], key=load_key,
            claims_cls=claims_cls,
            claims_options=claims_options,
            claims_params=claims_params,
        )
        # https://github.com/lepture/authlib/issues/259
        if claims.get('nonce_supported') is False:
            claims.params['nonce'] = None
        claims.validate(leeway=leeway)
        return UserInfo(claims)
