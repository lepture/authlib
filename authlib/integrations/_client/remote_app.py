import logging

from authlib.common.urls import urlparse
from authlib.common.security import generate_token
from authlib.consts import default_user_agent
from .errors import (
    MissingRequestTokenError,
    MissingTokenError,
    MismatchingStateError,
)

__all__ = ['RemoteApp']

log = logging.getLogger(__name__)
_req_token_tpl = '_{}_authlib_req_token_'
_callback_tpl = '_{}_authlib_callback_'
_state_tpl = '_{}_authlib_state_'
_code_verifier_tpl = '_{}_authlib_code_verifier_'


class RemoteApp(object):
    """A mixed OAuth client for OAuth 1 and OAuth 2.

    :param name: The name of the OAuth client, like: github, twitter
    :param fetch_token: A function to fetch access token from database
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
    DEFAULT_USER_AGENT = default_user_agent

    def __init__(
            self, name=None, fetch_token=None, update_token=None,
            client_id=None, client_secret=None,
            request_token_url=None, request_token_params=None,
            access_token_url=None, access_token_params=None,
            authorize_url=None, authorize_params=None,
            api_base_url=None, client_kwargs=None, server_metadata_url=None,
            oauth1_client_cls=None, oauth2_client_cls=None,
            compliance_fix=None, **kwargs):

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

        self.oauth1_client_cls = oauth1_client_cls
        self.oauth2_client_cls = oauth2_client_cls

        self.compliance_fix = compliance_fix
        self._fetch_token = fetch_token
        self._update_token = update_token

        if server_metadata_url:
            metadata = self._fetch_server_metadata(server_metadata_url)
            kwargs.update(metadata)

        self.server_metadata = kwargs

    def _send_token_update(self, token):
        if callable(self._update_token):
            self._update_token(token)

    def _generate_access_token_params(self, request):
        raise NotImplementedError()

    def _set_session_data(self, request, key, value):
        request.session[key] = value

    def _get_session_data(self, request, key):
        return request.session.pop(key, None)

    def _get_oauth_client(self):
        if self.request_token_url:
            session = self.oauth1_client_cls(
                self.client_id, self.client_secret,
                **self.client_kwargs
            )
        else:
            kwargs = {}
            kwargs.update(self.client_kwargs)
            kwargs.update(self.server_metadata)
            if self.authorize_url:
                kwargs['authorization_endpoint'] = self.authorize_url
            if self.access_token_url:
                kwargs['token_endpoint'] = self.access_token_url
            session = self.oauth2_client_cls(
                client_id=self.client_id,
                client_secret=self.client_secret,
                token_updater=self._send_token_update,
                **kwargs
            )
            # only OAuth2 has compliance_fix currently
            if self.compliance_fix:
                self.compliance_fix(session)

        session.headers['User-Agent'] = self.DEFAULT_USER_AGENT
        return session

    def save_authorize_state(self, request, redirect_uri=None, state=None):
        """Save ``redirect_uri`` and ``state`` into session during
        authorize step."""
        msg = 'Saving temporary data: redirect_uri: {!r}, state: {!r}'
        log.debug(msg.format(redirect_uri, state))
        if redirect_uri:
            key = _callback_tpl.format(self.name)
            self._set_session_data(request, key, redirect_uri)

        if state:
            key = _state_tpl.format(self.name)
            self._set_session_data(request, key, state)

    def save_temporary_data(self, request):
        if self.request_token_url:
            key = _req_token_tpl.format(self.name)
        else:
            key = _code_verifier_tpl.format(self.name)
        return lambda value: self._set_session_data(request, key, value)

    def retrieve_temporary_data(self, request, request_token=None):
        params = self._generate_access_token_params(request)
        if self.request_token_url:
            if request_token is None:
                req_key = _req_token_tpl.format(self.name)
                request_token = self._get_session_data(request, req_key)
            params['request_token'] = request_token
        else:
            request_state = params.pop('state', None)
            state_key = _state_tpl.format(self.name)
            state = self._get_session_data(request, state_key)
            if state:
                if state != request_state:
                    raise MismatchingStateError()
                params['state'] = state

            vf_key = _code_verifier_tpl.format(self.name)
            code_verifier = self._get_session_data(request, vf_key)
            if code_verifier:
                params['code_verifier'] = code_verifier

        cb_key = _callback_tpl.format(self.name)
        redirect_uri = self._get_session_data(request, cb_key)
        if redirect_uri:
            params['redirect_uri'] = redirect_uri

        log.debug('Retrieve temporary data: {!r}'.format(params))
        return params

    def create_authorization_url(
            self, redirect_uri=None, save_temporary_data=None, **kwargs):
        """Generate the authorization url and state for HTTP redirect.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param save_temporary_data: A function to save request token.
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

        with self._get_oauth_client() as session:
            if self.request_token_url:
                session.redirect_uri = redirect_uri
                params = {}
                if self.request_token_params:
                    params.update(self.request_token_params)
                token = session.fetch_request_token(
                    self.request_token_url, **params
                )
                log.debug('Fetch request token: {!r}'.format(token))
                # remember oauth_token, oauth_token_secret
                save_temporary_data(token)
                url = session.create_authorization_url(
                    authorization_endpoint,  **kwargs)
                return url, None
            else:
                session.redirect_uri = redirect_uri
                if session.code_challenge_method:
                    code_verifier = generate_token(20)
                    save_temporary_data(code_verifier)
                    kwargs['code_verifier'] = code_verifier
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

        with self._get_oauth_client() as session:
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
                token = session.fetch_token(token_endpoint, **kwargs)
            return token

    def request(self, method, url, token=None, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)
        with self._get_oauth_client() as session:
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
        return resp.json()
