from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from .rfc6749 import InsecureTransportError
from .rfc6749.parameters import (
    prepare_grant_uri,
    prepare_token_request,
    parse_authorization_code_response,
    parse_implicit_response,
)
from .rfc7009 import prepare_revoke_token_request
from .client_auth import TokenAuth, ClientAuth

DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


class OAuth2Client(object):
    """Construct a new OAuth 2 protocol client.

    :param session: Requests session object to communicate with
                    authorization server.
    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param client_auth_method: Client auth method for token endpoint.
    :param refresh_token_url: Refresh Token endpoint for auto refresh token.
    :param refresh_token_params: Extra parameters for refresh token endpoint.
    :param scope: Scope that you needed to access user resources.
    :param redirect_uri: Redirect URI you registered as callback.
    :param token: A dict of token attributes such as ``access_token``,
                  ``token_type`` and ``expires_at``.
    :param token_placement: The place to put token in HTTP request. Available
                            values: "header", "body", "uri".
    :param state: State string used to prevent CSRF. This will be given
                  when creating the authorization url and must be
                  supplied when parsing the authorization response.
    :param token_updater: A function for you to update token. It accept a
                          :class:`OAuth2Token` as parameter.
    """
    client_auth_class = ClientAuth
    token_auth_class = TokenAuth

    EXTRA_AUTHORIZE_PARAMS = (
        'response_mode', 'nonce', 'prompt', 'login_hint'
    )
    SESSION_REQUEST_PARAMS = (
        'allow_redirects', 'timeout', 'cookies', 'files',
        'proxies', 'hooks', 'stream', 'verify', 'cert', 'json'
    )

    def __init__(self, session, client_id=None,
                 client_secret=None, client_auth_method=None,
                 refresh_token_url=None, refresh_token_params=None,
                 scope=None, redirect_uri=None, token=None,
                 token_placement='header', state=None,
                 token_updater=None, **kwargs):

        self.session = session
        self.client_id = client_id

        if client_auth_method is None:
            if client_secret:
                client_auth_method = 'client_secret_basic'
            else:
                client_auth_method = 'none'

        self.client_auth = self.client_auth_class(
            client_id, client_secret, auth_method=client_auth_method)

        self.refresh_token_url = refresh_token_url
        self.refresh_token_params = refresh_token_params

        self.scope = scope
        self.redirect_uri = redirect_uri

        self.state = state
        self.token_updater = token_updater

        self._kwargs = kwargs

        self.compliance_hook = {
            'access_token_response': set(),
            'refresh_token_response': set(),
            'revoke_token_request': set(),
        }
        self.token_auth = self.token_auth_class(token, token_placement, self)

    @property
    def token(self):
        return self.token_auth.token

    @token.setter
    def token(self, token):
        self.token_auth.set_token(token)

    def create_authorization_url(self, url, state=None, **kwargs):
        """Generate an authorization URL and state.

        :param url: Authorization endpoint url, must be HTTPS.
        :param state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
        :param kwargs: Extra parameters to include.
        :return: authorization_url, state
        """
        state = state or self.state
        if state is None:
            state = generate_token()

        response_type = self._kwargs.get('response_type', 'code')
        response_type = kwargs.pop('response_type', response_type)
        if 'redirect_uri' not in kwargs:
            kwargs['redirect_uri'] = self.redirect_uri
        if 'scope' not in kwargs:
            kwargs['scope'] = self.scope

        for k in self.EXTRA_AUTHORIZE_PARAMS:
            if k not in kwargs and k in self._kwargs:
                kwargs[k] = self._kwargs[k]

        uri = prepare_grant_uri(
            url, client_id=self.client_id, response_type=response_type,
            state=state, **kwargs)
        return uri, state

    def fetch_token(self, url=None, code=None, authorization_response=None,
                    body='', auth=None, username=None, password=None,
                    method='POST', headers=None, **kwargs):
        """Generic method for fetching an access token from the token endpoint.

        :param url: Access Token endpoint URL, if not configured,
                    ``authorization_response`` is used to extract token from
                    its fragment (implicit way).
        :param code: Authorization code (if any)
        :param authorization_response: Authorization response URL, the callback
                                       URL of the request back to you. We can
                                       extract authorization code from it.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param username: Username of the resource owner for password grant.
        :param password: Password of the resource owner for password grant.
        :param method: The HTTP method used to make the request. Defaults
                       to POST, but may also be GET. Other methods should
                       be added as needed.
        :param headers: Dict to default request headers with.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        if url is None and authorization_response:
            return self.token_from_fragment(authorization_response)
        InsecureTransportError.check(url)

        session_kwargs = self._extract_session_request_params(kwargs)
        if code or authorization_response:
            body = self._prepare_authorization_code_body(
                code, authorization_response, body, **kwargs)
        elif username and password:
            if 'scope' not in kwargs and self.scope:
                kwargs['scope'] = self.scope
            body = prepare_token_request(
                'password', body, username=username,
                password=password, **kwargs)
        else:
            grant_type = kwargs.pop('grant_type', 'client_credentials')
            if 'scope' not in kwargs and self.scope:
                kwargs['scope'] = self.scope
            body = prepare_token_request(grant_type, body, **kwargs)

        if auth is None:
            auth = self.client_auth

        if headers is None:
            headers = DEFAULT_HEADERS

        return self._fetch_token(
            url, body=body, auth=auth, method=method,
            headers=headers, **session_kwargs
        )

    def _fetch_token(self, url, body='', headers=None, auth=None,
                     method='POST', **kwargs):
        if method.upper() == 'POST':
            resp = self.session.post(
                url, data=dict(url_decode(body)), headers=headers,
                auth=auth, **kwargs)
        else:
            resp = self.session.get(
                url, params=dict(url_decode(body)), headers=headers,
                auth=auth, **kwargs)

        for hook in self.compliance_hook['access_token_response']:
            resp = hook(resp)

        return self.parse_response_token(resp.json())

    def token_from_fragment(self, authorization_response):
        token = parse_implicit_response(authorization_response, self.state)
        return self.parse_response_token(token)

    def refresh_token(self, url=None, refresh_token=None, body='',
                      auth=None, headers=None, **kwargs):
        """Fetch a new access token using a refresh token.

        :param url: Refresh Token endpoint, must be HTTPS.
        :param refresh_token: The refresh_token to use.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        if url is None:
            url = self.refresh_token_url

        refresh_token = refresh_token or self.token.get('refresh_token')
        if self.refresh_token_params is not None:
            kwargs.update(self.refresh_token_params)

        session_kwargs = self._extract_session_request_params(kwargs)
        body = prepare_token_request(
            'refresh_token', body=body, scope=self.scope,
            refresh_token=refresh_token, **kwargs)

        if headers is None:
            headers = DEFAULT_HEADERS

        if auth is None:
            auth = self.client_auth

        return self._refresh_token(
            url, refresh_token=refresh_token, body=body, headers=headers,
            auth=auth, **session_kwargs)

    def _refresh_token(self, url, refresh_token=None, body='', headers=None,
                       auth=None, **kwargs):
        resp = self.session.post(
            url, data=dict(url_decode(body)), headers=headers,
            auth=auth, **kwargs)

        for hook in self.compliance_hook['refresh_token_response']:
            resp = hook(resp)

        token = self.parse_response_token(resp.json())
        if 'refresh_token' not in token:
            self.token['refresh_token'] = refresh_token

        if callable(self.token_updater):
            self.token_updater(self.token)

        return self.token

    def revoke_token(self, url, token, token_type_hint=None,
                     body=None, auth=None, headers=None, **kwargs):
        """Revoke token method defined via `RFC7009`_.

        :param url: Revoke Token endpoint, must be HTTPS.
        :param token: The token to be revoked.
        :param token_type_hint: The type of the token that to be revoked.
                                It can be "access_token" or "refresh_token".
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: A :class:`OAuth2Token` object (a dict too).

        .. _`RFC7009`: https://tools.ietf.org/html/rfc7009
        """
        if body is None:
            body = ''

        body, headers = prepare_revoke_token_request(
            token, token_type_hint, body, headers)

        for hook in self.compliance_hook['revoke_token_request']:
            url, headers, body = hook(url, headers, body)

        if auth is None:
            auth = self.client_auth

        session_kwargs = self._extract_session_request_params(kwargs)
        return self._revoke_token(
            url, body, auth=auth, headers=headers, **session_kwargs)

    def _revoke_token(self, url, body=None, auth=None, headers=None, **kwargs):
        return self.session.post(
            url, data=dict(url_decode(body)),
            headers=headers, auth=auth, **kwargs)

    def register_compliance_hook(self, hook_type, hook):
        """Register a hook for request/response tweaking.

        Available hooks are:

        * access_token_response: invoked before token parsing.
        * refresh_token_response: invoked before refresh token parsing.
        * protected_request: invoked before making a request.
        * revoke_token_request: invoked before revoking a token.
        """
        if hook_type == 'protected_request':
            self.token_auth.hooks.add(hook)
            return

        if hook_type not in self.compliance_hook:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self.compliance_hook)
        self.compliance_hook[hook_type].add(hook)

    def parse_response_token(self, token):
        if 'error' not in token:
            self.token = token
            return self.token

        error = token['error']
        description = token.get('error_description', error)
        self.handle_error(error, description)

    def _prepare_authorization_code_body(self, code, authorization_response,
                                         body, **kwargs):
        state = kwargs.pop('state', None)
        if not state:
            state = self.state

        if not code and authorization_response:
            params = parse_authorization_code_response(
                authorization_response,
                state=state
            )
            code = params['code']
        if 'redirect_uri' not in kwargs:
            kwargs['redirect_uri'] = self.redirect_uri
        return prepare_token_request(
            'authorization_code', body=body,
            code=code, state=state, **kwargs)

    def _extract_session_request_params(self, kwargs):
        """Extract parameters for session object from the passing ``**kwargs``."""
        rv = {}
        for k in self.SESSION_REQUEST_PARAMS:
            if k in kwargs:
                rv[k] = kwargs.pop(k)
        return rv

    @staticmethod
    def handle_error(error_type, error_description):
        raise ValueError('{}: {}'.format(error_type, error_description))
