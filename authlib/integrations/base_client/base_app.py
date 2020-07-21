import logging

from authlib.common.security import generate_token
from authlib.consts import default_user_agent
from .errors import (
    MismatchingStateError,
)

__all__ = ['BaseApp']

log = logging.getLogger(__name__)


class BaseApp(object):
    """The remote application for OAuth 1 and OAuth 2. It is used together
    with OAuth registry.

    :param name: The name of the OAuth client, like: github, twitter
    :param fetch_token: A function to fetch access token from database
    :param update_token: A function to update access token to database
    :param client_id: Client key of OAuth 1, or Client ID of OAuth 2
    :param client_secret: Client secret of OAuth 2, or Client Secret of OAuth 2
    :param request_token_url: Request Token endpoint for OAuth 1
    :param request_token_params: Extra parameters for Request Token endpoint
    :param access_token_url: Access Token endpoint for OAuth 1 and OAuth 2
    :param access_token_params: Extra parameters for Access Token endpoint
    :param authorize_url: Endpoint for user authorization of OAuth 1 or OAuth 2
    :param authorize_params: Extra parameters for Authorization Endpoint
    :param api_base_url: The base API endpoint to make requests simple
    :param client_kwargs: Extra keyword arguments for session
    :param server_metadata_url: Discover server metadata from this URL
    :param user_agent: Define a custom user agent to be used in HTTP request
    :param kwargs: Extra server metadata

    Create an instance of ``RemoteApp``. If ``request_token_url`` is configured,
    it would be an OAuth 1 instance, otherwise it is OAuth 2 instance::

        oauth1_client = RemoteApp(
            client_id='Twitter Consumer Key',
            client_secret='Twitter Consumer Secret',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            api_base_url='https://api.twitter.com/1.1/',
        )

        oauth2_client = RemoteApp(
            client_id='GitHub Client ID',
            client_secret='GitHub Client Secret',
            api_base_url='https://api.github.com/',
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            client_kwargs={'scope': 'user:email'},
        )
    """
    OAUTH_APP_CONFIG = None

    def __init__(
            self, framework, name=None, fetch_token=None, update_token=None,
            client_id=None, client_secret=None,
            request_token_url=None, request_token_params=None,
            access_token_url=None, access_token_params=None,
            authorize_url=None, authorize_params=None,
            api_base_url=None, client_kwargs=None, server_metadata_url=None,
            compliance_fix=None, client_auth_methods=None, user_agent=None, **kwargs):

        self.framework = framework
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.request_token_url = request_token_url
        self.request_token_params = request_token_params
        self.access_token_url = access_token_url
        self.access_token_params = access_token_params
        self.authorize_url = authorize_url
        self.authorize_params = authorize_params
        self.api_base_url = api_base_url
        self.client_kwargs = client_kwargs or {}

        self.compliance_fix = compliance_fix
        self.client_auth_methods = client_auth_methods
        self._fetch_token = fetch_token
        self._update_token = update_token
        self._user_agent = user_agent or default_user_agent

        self._server_metadata_url = server_metadata_url
        self.server_metadata = kwargs

    def _on_update_token(self, token, refresh_token=None, access_token=None):
        raise NotImplementedError()

    def _get_oauth_client(self, **kwargs):
        client_kwargs = {}
        client_kwargs.update(self.client_kwargs)
        client_kwargs.update(kwargs)
        if self.request_token_url:
            session = self.framework.oauth1_client_cls(
                self.client_id, self.client_secret,
                **client_kwargs
            )
        else:
            if self.authorize_url:
                client_kwargs['authorization_endpoint'] = self.authorize_url
            if self.access_token_url:
                client_kwargs['token_endpoint'] = self.access_token_url
            session = self.framework.oauth2_client_cls(
                client_id=self.client_id,
                client_secret=self.client_secret,
                update_token=self._on_update_token,
                **client_kwargs
            )
            if self.client_auth_methods:
                for f in self.client_auth_methods:
                    session.register_client_auth_method(f)
            # only OAuth2 has compliance_fix currently
            if self.compliance_fix:
                self.compliance_fix(session)

        session.headers['User-Agent'] = self._user_agent
        return session

    def _retrieve_oauth2_access_token_params(self, request, params):
        request_state = params.pop('state', None)
        state = self.framework.get_session_data(request, 'state')
        if state != request_state:
            raise MismatchingStateError()
        if state:
            params['state'] = state

        code_verifier = self.framework.get_session_data(request, 'code_verifier')
        if code_verifier:
            params['code_verifier'] = code_verifier
        return params

    def retrieve_access_token_params(self, request, request_token=None):
        """Retrieve parameters for fetching access token, those parameters come
        from request and previously saved temporary data in session.
        """
        params = self.framework.generate_access_token_params(self.request_token_url, request)
        if self.request_token_url:
            if request_token is None:
                request_token = self.framework.get_session_data(request, 'request_token')
            params['request_token'] = request_token
        else:
            params = self._retrieve_oauth2_access_token_params(request, params)

        redirect_uri = self.framework.get_session_data(request, 'redirect_uri')
        if redirect_uri:
            params['redirect_uri'] = redirect_uri

        log.debug('Retrieve temporary data: {!r}'.format(params))
        return params

    def save_authorize_data(self, request, **kwargs):
        """Save temporary data into session for the authorization step. These
        data can be retrieved later when fetching access token.
        """
        log.debug('Saving authorize data: {!r}'.format(kwargs))
        keys = [
            'redirect_uri', 'request_token',
            'state', 'code_verifier', 'nonce'
        ]
        for k in keys:
            if k in kwargs:
                self.framework.set_session_data(request, k, kwargs[k])

    @staticmethod
    def _create_oauth2_authorization_url(client, authorization_endpoint, **kwargs):
        rv = {}
        if client.code_challenge_method:
            code_verifier = kwargs.get('code_verifier')
            if not code_verifier:
                code_verifier = generate_token(48)
                kwargs['code_verifier'] = code_verifier
            rv['code_verifier'] = code_verifier
            log.debug('Using code_verifier: {!r}'.format(code_verifier))

        scope = kwargs.get('scope', client.scope)
        if scope and scope.startswith('openid'):
            # this is an OpenID Connect service
            nonce = kwargs.get('nonce')
            if not nonce:
                nonce = generate_token(20)
                kwargs['nonce'] = nonce
            rv['nonce'] = nonce

        url, state = client.create_authorization_url(
            authorization_endpoint, **kwargs)
        rv['url'] = url
        rv['state'] = state
        return rv

    def request(self, method, url, token=None, **kwargs):
        raise NotImplementedError()

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
        with self._get_oauth_client() as session:
            resp = session.request('GET', url, withhold_token=True)
            return resp.json()
