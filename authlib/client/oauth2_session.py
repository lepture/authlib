import logging
from requests import Session
from requests.auth import AuthBase
from authlib.oauth2.client import OAuth2Client
from authlib.oauth2.client_auth import ClientAuth, TokenAuth
from .errors import (
    OAuthError,
    MissingTokenError,
    UnsupportedTokenTypeError,
)
from ..deprecate import deprecate

__all__ = ['OAuth2Session', 'OAuth2Auth']

log = logging.getLogger(__name__)
DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
}


class OAuth2Auth(AuthBase, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""
    def __call__(self, req):
        if not self.token:
            raise MissingTokenError()
        self.ensure_refresh_token()
        try:
            req.url, req.headers, req.body = self.prepare(
                req.url, req.headers, req.body)
        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)
        return req


class OAuth2ClientAuth(AuthBase, ClientAuth):
    """Attaches OAuth Client Authentication to the given Request object.
    """
    def __call__(self, req):
        req.url, req.headers, req.body = self.prepare(
            req.method, req.url, req.headers, req.body
        )
        return req


class OAuth2Session(OAuth2Client, Session):
    """Construct a new OAuth 2 client requests session.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param token_endpoint_auth_method: Client auth method for token endpoint.
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
    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth

    def __init__(self, client_id=None, client_secret=None,
                 token_endpoint_auth_method=None,
                 refresh_token_url=None, refresh_token_params=None,
                 scope=None, redirect_uri=None, token=None,
                 token_placement='header', state=None,
                 token_updater=None, **kwargs):
        Session.__init__(self)
        OAuth2Client.__init__(
            self, session=self,
            client_id=client_id, client_secret=client_secret,
            client_auth_method=token_endpoint_auth_method,
            refresh_token_url=refresh_token_url,
            refresh_token_params=refresh_token_params,
            scope=scope, redirect_uri=redirect_uri,
            token=token, token_placement=token_placement,
            state=state, token_updater=token_updater, **kwargs
        )
        self.token_endpoint_auth_method = token_endpoint_auth_method

    def register_client_auth_method(self, func):
        """Extend client authenticate for token endpoint.

        :param func: a function to sign the request
        """
        self.client_auth.register(self.token_endpoint_auth_method, func)

    def authorization_url(self, url, state=None, **kwargs):  # pragma: no cover
        deprecate('Use "create_authorization_url" instead', '0.12')
        return self.create_authorization_url(url, state, **kwargs)

    def fetch_access_token(self, url=None, **kwargs):
        """Alias for fetch_token."""
        return self.fetch_token(url, **kwargs)

    def request(self, method, url, withhold_token=False, auth=None, **kwargs):
        """Send request with auto refresh token feature (if available)."""
        if self.token and not withhold_token:
            if auth is None:
                auth = self.token_auth
        return super(OAuth2Session, self).request(
            method, url, auth=auth, **kwargs)

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)
