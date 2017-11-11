import logging
from .oauth1 import OAuth1Session
from .oauth2 import OAuth2Session
from .errors import OAuthException
from ..specs.rfc6749 import OAuth2Token
from ..common.urls import urlparse

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
                 client_kwargs=None, **kwargs):
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
        self.compliance_fix = None

        self._kwargs = kwargs
        self._sess = None

        self._hooks = {
            'access_token_getter': None,
            'request_token_getter': None,
            'request_token_setter': None,
            'authorize_redirect': None
        }

    def register_hook(self, hook_type, f):
        """Register a hook for OAuthClient.

        :param hook_type: Type name of the hook.
        :param f: A function that will be bind with the given hook type.

        Available hook types are:

        * access_token_getter: fetch access token from database.
        * request_token_getter: get the temporary request token (for OAuth 1).
        * request_token_setter: the temporary request token (for OAuth 1).
        * authorize_redirect: invoke to handle HTTP redirect.
        """
        if hook_type not in self._hooks:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self._hooks)
        self._hooks[hook_type] = f

    def authorize_redirect(self, callback_uri=None, **kwargs):
        """Generate the authorize redirect with the given
        :meth:`authorize_redirect` hook.

        :param callback_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.

        You need to :meth:`register_hook` a `authorize_redirect` hook, which
        accepts three parameters::

            def handle_authorize_redirect(url, callback_uri, state):
                # this is a pseudo method, you need to construct it yourself
                if callback_uri:
                    # for later use
                    session['callback_uri'] = callback_uri
                if state:
                    # for later security check
                    session['state'] = state
                return make_redirect_response(url, status_code=302)

            client.register_hook('authorize_redirect', handle_authorize_redirect)
        """
        redirect = self._hooks['authorize_redirect']
        assert callable(redirect), 'missing authorize_redirect'

        if self.request_token_url:
            set_token = self._hooks['request_token_setter']
            assert callable(set_token), 'missing request_token_setter'

            self.session.callback_uri = callback_uri
            params = {}
            if self.request_token_params:
                params.update(self.request_token_params)
            token = self.session.fetch_request_token(
                self.request_token_url, **params
            )
            # remember oauth_token, oauth_token_secret
            set_token(token)
            url = self.session.authorization_url(
                self.authorize_url,  **kwargs)
            self.session.callback_uri = None
            state = None
        else:
            self.session.redirect_uri = callback_uri
            url, state = self.session.authorization_url(
                self.authorize_url, **kwargs)
        return redirect(url, callback_uri, state)

    def fetch_access_token(self, callback_uri=None, **params):
        """Fetch access token in one step.

        :param callback_uri: Callback or Redirect URI that is used in
                             previous :meth:`authorize_redirect`.
        :param params: Extra parameters to fetch access token.
        :return: A token dict.
        """
        if self.request_token_url:
            get_request_token = self._hooks['request_token_getter']
            assert callable(get_request_token), 'missing request_token_getter'

            self.session.callback_uri = callback_uri
            token = get_request_token()
            # merge token with verifier
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
        return self._sess

    def set_token(self, token):
        if not self.request_token_url and isinstance(token, dict):
            token = OAuth2Token(token)
        self.session.token = token

    def _get_access_token(self):
        func = self._hooks['access_token_getter']
        assert callable(func), 'missing access_token_getter'
        rv = func()
        if rv is None:
            raise OAuthException('No token available', type='token_missing')
        return rv

    def request(self, method, url, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)
        if not self.session.token:
            self.set_token(self._get_access_token())
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
