import logging
from requests import Session
from requests.auth import HTTPBasicAuth
from ..common.security import generate_token, is_secure_transport
from ..common.urls import url_decode
from ..specs.rfc6749.grant import (
    prepare_grant_uri,
    prepare_token_request,
    parse_authorization_code_response,
    parse_implicit_response,
)
from ..specs.rfc6749 import OAuth2Token
from ..specs.rfc6749 import CustomOAuth2Error, InsecureTransportError
from ..specs.rfc6750 import BearToken, ExpiredTokenError

__all__ = ['OAuth2Session']

log = logging.getLogger(__name__)
DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


class OAuth2Session(Session):
    def __init__(self, client_id=None, client_secret=None,
                 auto_refresh_url=None, auto_refresh_kwargs=None,
                 scope=None, redirect_uri=None,
                 token=None, token_placement='headers',
                 state=None, token_updater=None):
        """Construct a new OAuth 2 client requests session.

        :param client_id:
        :param client_secret:
        :param auto_refresh_url:
        :param auto_refresh_kwargs:
        :param scope:
        :param redirect_uri: Redirect URI you registered as callback.
        :param token: A dict of token attributes such as ``access_token``,
                      ``token_type`` and ``expires_at``.
        :param state: State string used to prevent CSRF. This will be given
                      when creating the authorization url and must be
                      supplied when parsing the authorization response.
        :param token_updater:
        """
        super(OAuth2Session, self).__init__()

        self.client_id = client_id
        self.client_secret = client_secret
        self.auto_refresh_url = auto_refresh_url
        self.auto_refresh_kwargs = auto_refresh_kwargs
        self.scope = scope
        self.redirect_uri = redirect_uri
        if isinstance(token, dict) and not isinstance(token, OAuth2Token):
            token = OAuth2Token(token)
        self.token = token
        self.token_placement = token_placement
        self.state = state
        self.token_updater = token_updater

        self.compliance_hook = {
            'access_token_response': set(),
            'refresh_token_response': set(),
            'protected_request': set(),
        }

    @property
    def token_cls(self):
        if not self.token:
            return None

        token_type = self.token['token_type'].lower()
        if token_type == 'bearer':
            return BearToken

    def authorization_url(self, url, state=None, **kwargs):
        state = state or self.state
        if state is None:
            state = generate_token()

        uri = prepare_grant_uri(
            url, client_id=self.client_id, response_type='code',
            redirect_uri=self.redirect_uri, scope=self.scope,
            state=state, **kwargs
        )
        return uri, state

    def fetch_access_token(
            self, url=None, code=None, authorization_response=None,
            body='', auth=None, username=None, password=None, method='POST',
            timeout=None, headers=None, verify=True, proxies=None, **kwargs):

        if url is None and authorization_response:
            return self.token_from_fragment(authorization_response)

        if not is_secure_transport(url):
            raise InsecureTransportError()

        if not code and authorization_response:
            params = parse_authorization_code_response(
                authorization_response,
                state=self.state
            )
            code = params['code']

        body = prepare_token_request(
            'authorization_code',
            code=code, body=body,
            redirect_uri=self.redirect_uri,
            state=self.state,
            **kwargs
        )

        if auth is None:
            if username and password:
                auth = HTTPBasicAuth(username, password)
            else:
                client_secret = self.client_secret
                if client_secret is None:
                    client_secret = ''
                auth = HTTPBasicAuth(self.client_id, client_secret)

        if headers is None:
            headers = DEFAULT_HEADERS

        if method.upper() == 'POST':
            resp = self.post(
                url, data=dict(url_decode(body)), timeout=timeout,
                headers=headers, auth=auth, verify=verify, proxies=proxies
            )
        else:
            resp = self.get(
                url, params=dict(url_decode(body)), timeout=timeout,
                headers=headers, auth=auth, verify=verify, proxies=proxies
            )

        for hook in self.compliance_hook['access_token_response']:
            resp = hook(resp)

        params = resp.json()
        return self._parse_and_validate_token(params, resp.status_code)

    def fetch_token(self, url, **kwargs):
        """Alias for fetch_access_token. Compatible with requests-oauthlib."""
        return self.fetch_access_token(url, **kwargs)

    def token_from_fragment(self, authorization_response):
        params = parse_implicit_response(authorization_response, self.state)
        return self._parse_and_validate_token(params)

    def refresh_token(self, url, refresh_token=None, body='', auth=None,
                      timeout=None, headers=None, verify=True,
                      proxies=None, **kwargs):

        refresh_token = refresh_token or self.token.get('refresh_token')
        kwargs.update(self.auto_refresh_kwargs)

        body = prepare_token_request(
            'refresh_token', body=body, scope=self.scope,
            refresh_token=refresh_token, **kwargs
        )

        if headers is None:
            headers = DEFAULT_HEADERS

        resp = self.post(
            url, data=dict(url_decode(body)), auth=auth, timeout=timeout,
            headers=headers, verify=verify, withhold_token=True, proxies=proxies
        )
        for hook in self.compliance_hook['refresh_token_response']:
            resp = hook(resp)

        params = resp.json()
        self._parse_and_validate_token(params, resp.status_code)
        if 'refresh_token' not in self.token:
            self.token['refresh_token'] = refresh_token

        if callable(self.token_updater):
            self.token_updater(self.token)
        return self.token

    def request(self, method, url, data=None, headers=None,
                withhold_token=False, **kwargs):

        if self.token and not withhold_token:
            if self.token.is_expired():
                if not self.auto_refresh_url:
                    raise ExpiredTokenError()
                auth = kwargs.pop('auth', None)
                if auth is None and self.client_id and self.client_secret:
                    auth = HTTPBasicAuth(self.client_id, self.client_secret)

                self.refresh_token(
                    self.auto_refresh_url, auth=auth, **kwargs
                )

            tok = self.token_cls(self.token['access_token'])
            url, headers, data = tok.add_token(
                url, headers, data, self.token_placement
            )

            for hook in self.compliance_hook['protected_request']:
                url, headers, data = hook(url, headers, data)

        return super(OAuth2Session, self).request(
            method, url, headers=headers, data=data, **kwargs)

    def register_compliance_hook(self, hook_type, hook):
        """Register a hook for request/response tweaking.

        Available hooks are:
        * access_token_response: invoked before token parsing.
        * refresh_token_response: invoked before refresh token parsing.
        * protected_request: invoked before making a request.
        """
        if hook_type not in self.compliance_hook:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self.compliance_hook)
        self.compliance_hook[hook_type].add(hook)

    def _parse_and_validate_token(self, params, status_code=400):
        if 'error' not in params:
            self.token = OAuth2Token(params)
            return self.token

        error = params['error']
        description = params.get('description')
        uri = params.get('error_uri'),
        state = params.get('state')
        raise CustomOAuth2Error(error, description, status_code, uri, state)
