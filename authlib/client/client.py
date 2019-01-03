import logging

from .oauth1_session import OAuth1Session
from .oauth2_session import OAuth2Session
from .errors import (
    MissingRequestTokenError,
    MissingTokenError,
)
from ..oauth2.rfc7636 import create_s256_code_challenge
from ..common.urls import urlparse
from ..common.security import generate_token
from ..consts import default_user_agent

__all__ = ['OAUTH_CLIENT_PARAMS', 'OAuthClient']

log = logging.getLogger(__name__)

OAUTH_CLIENT_PARAMS = (
    'client_id', 'client_secret',
    'request_token_url', 'request_token_params',
    'access_token_url', 'access_token_params',
    'refresh_token_url', 'refresh_token_params',
    'authorize_url', 'authorize_params',
    'api_base_url', 'client_kwargs',
    'server_metadata_url',
)


class OAuthClient(object):
    """A mixed OAuth client for OAuth 1 and OAuth 2.

    :param client_id: Client key of OAuth 1, or Client ID of OAuth 2
    :param client_secret: Client secret of OAuth 2, or Client Secret of OAuth 2
    :param request_token_url: Request Token endpoint for OAuth 1
    :param request_token_params: Extra parameters for Request Token endpoint
    :param access_token_url: Access Token endpoint for OAuth 1 and OAuth 2
    :param access_token_params: Extra parameters for Access Token endpoint
    :param refresh_token_url: Refresh Token endpoint for OAuth 2 (if any)
    :param refresh_token_params: Extra parameters for Refresh Token endpoint
    :param authorize_url: Endpoint for user authorization of OAuth 1 ro OAuth 2
    :param authorize_params: Extra parameters for Authorization Endpoint
    :param api_base_url: The base API endpoint to make requests simple
    :param client_kwargs: Extra keyword arguments for session
    :param server_metadata_url: Discover server metadata from this URL
    :param kwargs: Extra keyword arguments

    Create an instance of OAuthClient. If ``request_token_url`` is configured,
    it would be an OAuth 1 instance, otherwise it is OAuth 2 instance::

        oauth1_client = OAuthClient(
            client_id='Twitter Consumer Key',
            client_secret='Twitter Consumer Secret',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            api_base_url='https://api.twitter.com/1.1/',
        )

        oauth2_client = OAuthClient(
            client_id='GitHub Client ID',
            client_secret='GitHub Client Secret',
            api_base_url='https://api.github.com/',
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            client_kwargs={'scope': 'user:email'},
        )
    """
    DEFAULT_USER_AGENT = default_user_agent

    def __init__(
            self, client_id=None, client_secret=None,
            request_token_url=None, request_token_params=None,
            access_token_url=None, access_token_params=None,
            refresh_token_url=None, refresh_token_params=None,
            authorize_url=None, authorize_params=None,
            api_base_url=None, client_kwargs=None,
            server_metadata_url=None,
            compliance_fix=None, **kwargs):

        self.client_id = client_id
        self.client_secret = client_secret
        self.request_token_url = request_token_url
        self.request_token_params = request_token_params
        self.access_token_url = access_token_url
        self.access_token_params = access_token_params
        self.refresh_token_url = refresh_token_url
        self.refresh_token_params = refresh_token_params
        self.authorize_url = authorize_url
        self.authorize_params = authorize_params
        self.api_base_url = api_base_url

        self.client_kwargs = client_kwargs or {}
        self.compliance_fix = compliance_fix

        self.server_metadata = {}

        self._fetch_token = None
        self._kwargs = kwargs

        if server_metadata_url:
            self._fetch_server_metadata(server_metadata_url)

    def generate_authorize_redirect(
            self, redirect_uri=None, save_request_token=None, **kwargs):
        """Generate the authorization url and state for HTTP redirect.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param save_request_token: A function to save request token.
        :param kwargs: Extra parameters to include.
        :return: (url, state)
        """
        authorization_endpoint = self.authorize_url
        if not authorization_endpoint and not self.request_token_url:
            authorization_endpoint = self.server_metadata.get('authorization_endpoint')

        if not authorization_endpoint:
            raise RuntimeError('Missing "authorize_url" value')

        if self.authorize_params:
            kwargs.update(self.authorize_params)

        with self._get_session() as session:
            if self.request_token_url:
                session.redirect_uri = redirect_uri
                params = {}
                if self.request_token_params:
                    params.update(self.request_token_params)
                token = session.fetch_request_token(
                    self.request_token_url, **params
                )
                # remember oauth_token, oauth_token_secret
                save_request_token(token)
                url = session.create_authorization_url(
                    authorization_endpoint,  **kwargs)
                return url, None

            session.redirect_uri = redirect_uri
            return session.create_authorization_url(
                authorization_endpoint, **kwargs)

    def fetch_access_token(self, redirect_uri=None, request_token=None,
                           **params):
        """Fetch access token in one step.

        :param redirect_uri: Callback or Redirect URI that is used in
                             previous :meth:`authorize_redirect`.
        :param request_token: A previous request token for OAuth 1.
        :param params: Extra parameters to fetch access token.
        :return: A token dict.
        """
        token_endpoint = self.access_token_url
        if not token_endpoint and not self.request_token_url:
            token_endpoint = self.server_metadata.get('token_endpoint')

        with self._get_session() as session:
            if self.request_token_url:
                session.redirect_uri = redirect_uri
                if request_token is None:
                    raise MissingRequestTokenError()
                # merge request token with verifier
                token = {}
                token.update(request_token)
                token.update(params)
                session.token = token
                kwargs = self.access_token_params or {}
                token = session.fetch_access_token(token_endpoint, **kwargs)
                session.redirect_uri = None
            else:
                session.redirect_uri = redirect_uri
                kwargs = {}
                if self.access_token_params:
                    kwargs.update(self.access_token_params)
                kwargs.update(params)
                token = session.fetch_access_token(token_endpoint, **kwargs)
            return token

    def _get_session(self):
        if self.request_token_url:
            session = OAuth1Session(
                self.client_id, self.client_secret,
                **self.client_kwargs
            )
        else:
            session = OAuth2Session(
                client_id=self.client_id,
                client_secret=self.client_secret,
                refresh_token_url=self.refresh_token_url,
                refresh_token_params=self.refresh_token_params,
                **self.client_kwargs
            )
            # only OAuth2 has compliance_fix currently
            if self.compliance_fix:
                self.compliance_fix(session)

        session.headers['User-Agent'] = self.DEFAULT_USER_AGENT
        return session

    def add_code_challenge(self, save_code_verifier, kwargs):
        code_challenge_method = self._kwargs.get('code_challenge_method')
        # only support S256
        if code_challenge_method == 'S256':
            verifier = kwargs.get('code_verifier')
            if not verifier:
                verifier = generate_token(20)

            save_code_verifier(verifier)
            kwargs['code_challenge'] = create_s256_code_challenge(verifier)
            kwargs['code_challenge_method'] = code_challenge_method
        return kwargs

    def request(self, method, url, token=None, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)
        with self._get_session() as session:
            if kwargs.get('withhold_token'):
                return session.request(method, url, **kwargs)

            request = kwargs.pop('request', None)
            if token is None and self._fetch_token and request:
                token = self._fetch_token(request)
            if token is None:
                raise MissingTokenError()

            session.token = token
            return session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        """Invoke GET http request.

        If ``api_base_url`` configured, shortcut is available::

            client.get('users/lepture')
        """
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        """Invoke POST http request.

        If ``api_base_url`` configured, shortcut is available::

            client.post('timeline', json={'text': 'Hi'})
        """
        return self.request('POST', url, **kwargs)

    def patch(self, url, **kwargs):
        """Invoke PATCH http request.

        If ``api_base_url`` configured, shortcut is available::

            client.patch('profile', json={'name': 'Hsiaoming Yang'})
        """
        return self.request('PATCH', url, **kwargs)

    def put(self, url, **kwargs):
        """Invoke PUT http request.

        If ``api_base_url`` configured, shortcut is available::

            client.put('profile', json={'name': 'Hsiaoming Yang'})
        """
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        """Invoke DELETE http request.

        If ``api_base_url`` configured, shortcut is available::

            client.delete('posts/123')
        """
        return self.request('DELETE', url, **kwargs)

    def _fetch_server_metadata(self, url):
        resp = self.get(url, withhold_token=True)
        data = resp.json()
        self.server_metadata = data
