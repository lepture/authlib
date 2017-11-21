import logging
from .oauth1 import OAuth1Session
from .oauth2 import OAuth2Session
from .errors import OAuthException
from ..specs.rfc6749 import OAuth2Token
from ..common.urls import urlparse
from ..consts import default_user_agent

__all__ = ['OAuthClient']

log = logging.getLogger(__name__)


class OAuthClient(object):
    """A mixed OAuth client for OAuth 1 and OAuth 2.

    :param client_key: Consumer key of OAuth 1, or Client ID of OAuth 2
    :param client_secret: Consumer secret of OAuth 2, or Client Secret of OAuth 2
    :param request_token_url: Request Token endpoint for OAuth 1
    :param request_token_params: Extra parameters for Request Token endpoint
    :param access_token_url: Access Token endpoint for OAuth 1 and OAuth 2
    :param access_token_params: Extra parameters for Access Token endpoint
    :param refresh_token_url: Refresh Token endpoint for OAuth 2 (if any)
    :param refresh_token_params: Extra paramters for Refresh Token endpoint
    :param authorize_url: Endpoint for user authorization of OAuth 1 ro OAuth 2
    :param api_base_url: A base URL endpoint to make requests simple
    :param client_kwargs: Extra keyword arguments for session
    :param kwargs: Extra keyword arguments

    Create an instance of OAuthClient. If ``request_token_url`` is configured,
    it would be an OAuth 1 instance, otherwise it is OAuth 2 instance::

        oauth1_client = OAuthClient(
            client_key='Twitter Consumer Key',
            client_secret='Twitter Consumer Secret',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            api_base_url='https://api.twitter.com/1.1/',
        )

        oauth2_client = OAuthClient(
            client_key='GitHub Client ID',
            client_secret='GitHub Client Secret',
            api_base_url='https://api.github.com/',
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            client_kwargs={'scope': 'user:email'},
        )
    """
    def __init__(self, client_key=None, client_secret=None,
                 request_token_url=None, request_token_params=None,
                 access_token_url=None, access_token_params=None,
                 refresh_token_url=None, refresh_token_params=None,
                 authorize_url=None, api_base_url=None,
                 client_kwargs=None, compliance_fix=None, **kwargs):
        self.client_key = client_key
        self.client_secret = client_secret
        self.request_token_url = request_token_url
        self.request_token_params = request_token_params
        self.access_token_url = access_token_url
        self.access_token_params = access_token_params
        self.refresh_token_url = refresh_token_url
        self.refresh_token_params = refresh_token_params
        self.authorize_url = authorize_url
        self.api_base_url = api_base_url
        self.client_kwargs = client_kwargs or {}
        self.compliance_fix = compliance_fix

        self._kwargs = kwargs
        self._sess = None

    def generate_authorize_redirect(
            self, callback_uri=None, save_request_token=None, **kwargs):
        """Generate the authorize redirect.

        :param callback_uri: Callback or redirect URI for authorization.
        :param save_request_token: A function to save request token.
        :param kwargs: Extra parameters to include.
        :return: (url, state)
        """
        if self.request_token_url:
            self.session.callback_uri = callback_uri
            params = {}
            if self.request_token_params:
                params.update(self.request_token_params)
            token = self.session.fetch_request_token(
                self.request_token_url, **params
            )
            # remember oauth_token, oauth_token_secret
            save_request_token(token)
            url = self.session.authorization_url(
                self.authorize_url,  **kwargs)
            self.session.callback_uri = None
            state = None
        else:
            self.session.redirect_uri = callback_uri
            url, state = self.session.authorization_url(
                self.authorize_url, **kwargs)
        return url, state

    def fetch_access_token(self, callback_uri=None, request_token=None,
                           **params):
        """Fetch access token in one step.

        :param callback_uri: Callback or Redirect URI that is used in
                             previous :meth:`authorize_redirect`.
        :param request_token: A previous request token for OAuth 1.
        :param params: Extra parameters to fetch access token.
        :return: A token dict.
        """
        if self.request_token_url:
            self.session.callback_uri = callback_uri
            if request_token is None:
                raise OAuthException('Missing request token')
            # merge request token with verifier
            token = {}
            token.update(request_token)
            token.update(params)
            self.session.token = token
            kwargs = self.access_token_params or {}
            token = self.session.fetch_access_token(
                self.access_token_url, **kwargs)
            self.session.callback_uri = None
        else:
            self.session.redirect_uri = callback_uri
            kwargs = {}
            if self.access_token_params:
                kwargs.update(self.access_token_params)
            kwargs.update(params)
            token = self.session.fetch_access_token(
                self.access_token_url, **kwargs)
        return token

    @property
    def session(self):
        """OAuth 1/2 Session for requests. Initialized lazily.

        If ``request_token_url`` is configured, it is a
        :class:`OAuth1Session`, otherwise it is a :class:`OAuth2Session`.
        """
        if self._sess:
            return self._sess

        if self.request_token_url:
            self._sess = OAuth1Session(
                client_key=self.client_key,
                client_secret=self.client_secret,
                **self.client_kwargs
            )
        else:
            self._sess = OAuth2Session(
                client_id=self.client_key,
                client_secret=self.client_secret,
                refresh_token_url=self.refresh_token_url,
                refresh_token_params=self.refresh_token_params,
                **self.client_kwargs
            )
            # only OAuth2 has compliance_fix currently
            if self.compliance_fix:
                self.compliance_fix(self._sess)
        self._sess.headers['User-Agent'] = default_user_agent
        return self._sess

    def set_token(self, token):
        if token is None:
            raise OAuthException('No token available', type='token_missing')
        if not self.request_token_url and isinstance(token, dict):
            token = OAuth2Token(token)
        self.session.token = token

    def get_token(self):
        raise NotImplementedError()

    def request(self, method, url, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)
        if kwargs.get('withhold_token'):
            return self.session.request(method, url, **kwargs)
        if not self.session.token:
            self.set_token(self.get_token())
        return self.session.request(method, url, **kwargs)

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
