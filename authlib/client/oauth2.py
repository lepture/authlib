import logging
from requests import Session
from requests.auth import HTTPBasicAuth
from ..common.security import generate_token
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
from ..specs.rfc7009 import prepare_revoke_token_request

__all__ = ['OAuth2Session']

log = logging.getLogger(__name__)
DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


class OAuth2Session(Session):
    """Construct a new OAuth 2 client requests session.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param refresh_token_url: Refresh Token endpoint for auto refresh token.
    :param refresh_token_params: Extra parameters for refresh token endpoint.
    :param scope: Scope that you needed to access user resources.
    :param redirect_uri: Redirect URI you registered as callback.
    :param token: A dict of token attributes such as ``access_token``,
                  ``token_type`` and ``expires_at``.
    :param state: State string used to prevent CSRF. This will be given
                  when creating the authorization url and must be
                  supplied when parsing the authorization response.
    :param token_updater: A function for you to update token. It accept a
                          :class:`OAuth2Token` as parameter.
    """
    def __init__(self, client_id=None, client_secret=None,
                 refresh_token_url=None, refresh_token_params=None,
                 scope=None, redirect_uri=None,
                 token=None, token_placement='headers',
                 state=None, token_updater=None, **kwargs):
        super(OAuth2Session, self).__init__()

        self.client_id = client_id
        self.client_secret = client_secret

        if refresh_token_url is None and 'auto_refresh_url' in kwargs:
            # compatible with requests-oauthlib
            refresh_token_url = kwargs.pop('auto_refresh_url')
        self.refresh_token_url = refresh_token_url

        if refresh_token_params is None and 'auto_refresh_kwargs' in kwargs:
            # compatible with requests-oauthlib
            refresh_token_params = kwargs.pop('auto_refresh_kwargs')
        self.refresh_token_params = refresh_token_params

        self.scope = scope
        self.redirect_uri = redirect_uri

        if isinstance(token, dict) and not isinstance(token, OAuth2Token):
            token = OAuth2Token(token)
        self.token = token
        self.token_placement = token_placement

        self.state = state
        self.token_updater = token_updater

        self._kwargs = kwargs

        self.compliance_hook = {
            'access_token_response': set(),
            'refresh_token_response': set(),
            'protected_request': set(),
            'revoke_token_request': set(),
        }

    @property
    def token_cls(self):
        if not self.token:
            return None

        token_type = self.token['token_type'].lower()
        if token_type == 'bearer':
            return BearToken

    def authorization_url(self, url, state=None, **kwargs):
        """Generate an authorization URL.

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
        uri = prepare_grant_uri(
            url, client_id=self.client_id, response_type=response_type,
            redirect_uri=self.redirect_uri, scope=self.scope,
            state=state, **kwargs
        )
        return uri, state

    def fetch_access_token(
            self, url=None, code=None, authorization_response=None,
            body='', auth=None, username=None, password=None, method='POST',
            headers=None, timeout=None, verify=True, proxies=None, **kwargs):

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
        :param username: Username used by legacy clients.
        :param password: Password used by legacy clients.
        :param method: The HTTP method used to make the request. Defaults
                       to POST, but may also be GET. Other methods should
                       be added as needed.
        :param headers: Dict to default request headers with.
        :param timeout: Timeout of the request in seconds.
        :param verify: Verify SSL certificate.
        :param proxies: Proxies to use with requests.
        :param kwargs: Extra parameters to include in the token request.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        if url is None and authorization_response:
            return self.token_from_fragment(authorization_response)

        InsecureTransportError.check(url)

        body = self._prepare_authorization_code_body(
            code, authorization_response, body, **kwargs)

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
                headers=headers, auth=auth, verify=verify, proxies=proxies,
                withhold_token=True,
            )
        else:
            resp = self.get(
                url, params=dict(url_decode(body)), timeout=timeout,
                headers=headers, auth=auth, verify=verify, proxies=proxies,
                withhold_token=True,
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
                      headers=None, timeout=None, verify=True,
                      proxies=None, **kwargs):

        """Fetch a new access token using a refresh token.

        :param url: Refresh Token endpoint, must be HTTPS.
        :param refresh_token: The refresh_token to use.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :param timeout: Timeout of the request in seconds.
        :param verify: Verify SSL certificate.
        :param proxies: Proxies to use with requests.
        :param kwargs: Extra parameters to include in the token request.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        refresh_token = refresh_token or self.token.get('refresh_token')
        kwargs.update(self.refresh_token_params)

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

    def revoke_token(self, url, token, token_type_hint=None,
                     body=None, auth=None, headers=None, timeout=None,
                     verify=True, proxies=None, **kwargs):
        """Revoke token method defined via `RFC7009`_.

        :param url: Revoke Token endpoint, must be HTTPS.
        :param token: The token to be revoked.
        :param token_type_hint: The type of the token that to be revoked.
                                It can be "access_token" or "refresh_token".
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :param timeout: Timeout of the request in seconds.
        :param verify: Verify SSL certificate.
        :param proxies: Proxies to use with requests.
        :param kwargs: Extra parameters to include in the token request.
        :return: A :class:`OAuth2Token` object (a dict too).

        .. _`RFC7009`: https://tools.ietf.org/html/rfc7009
        """
        if body is None:
            body = ''

        data, headers = prepare_revoke_token_request(
            token, token_type_hint, body, headers)

        for hook in self.compliance_hook['revoke_token_request']:
            url, headers, data = hook(url, headers, data)

        if auth is None:
            client_secret = self.client_secret
            if client_secret is None:
                client_secret = ''
            auth = HTTPBasicAuth(self.client_id, client_secret)

        return self.post(
            url, data=dict(url_decode(body)), timeout=timeout,
            headers=headers, auth=auth, verify=verify, proxies=proxies,
            withhold_token=True,
        )

    def request(self, method, url, data=None, headers=None,
                withhold_token=False, **kwargs):

        if self.token and not withhold_token:
            if self.token.is_expired():
                if not self.refresh_token_url:
                    raise ExpiredTokenError()
                auth = kwargs.pop('auth', None)
                if auth is None and self.client_id and self.client_secret:
                    auth = HTTPBasicAuth(self.client_id, self.client_secret)

                self.refresh_token(
                    self.refresh_token_url, auth=auth, **kwargs
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
        description = params.get('error_description')
        uri = params.get('error_uri'),
        state = params.get('state')
        raise CustomOAuth2Error(error, description, status_code, uri, state)

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
        return prepare_token_request(
            'authorization_code',
            client=self.client_id,
            code=code, body=body,
            redirect_uri=self.redirect_uri,
            state=state,
            **kwargs
        )
