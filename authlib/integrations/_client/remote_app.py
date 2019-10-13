import logging

from authlib.common.urls import urlparse
from .base_app import BaseApp
from .errors import (
    MissingRequestTokenError,
    MissingTokenError,
)

__all__ = ['RemoteApp']

log = logging.getLogger(__name__)


class RemoteApp(BaseApp):
    def _load_server_metadata(self):
        if self._server_metadata_url:
            metadata = self._fetch_server_metadata(self._server_metadata_url)
            self._server_metadata_url = None  # only load once
            self.server_metadata.update(metadata)
        return self.server_metadata

    def _send_token_update(self, token, refresh_token=None, access_token=None):
        if callable(self._update_token):
            self._update_token(
                token,
                refresh_token=refresh_token,
                access_token=access_token,
            )

    def _generate_access_token_params(self, request):
        raise NotImplementedError()

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
        metadata = self._load_server_metadata()
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
        metadata = self._load_server_metadata()
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

        with self._get_oauth_client() as session:
            request = kwargs.pop('request', None)
            if kwargs.get('withhold_token'):
                return session.request(method, url, **kwargs)

            if token is None and self._fetch_token and request:
                token = self._fetch_token(request)
            if token is None:
                raise MissingTokenError()

            session.token = token
            return session.request(method, url, **kwargs)
