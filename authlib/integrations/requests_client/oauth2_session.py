from requests import Session
from requests.auth import AuthBase
from authlib.oauth2.client import OAuth2Client
from authlib.oauth2.auth import ClientAuth, TokenAuth
from ..client_errors import (
    OAuthError,
    InvalidTokenError,
    MissingTokenError,
    UnsupportedTokenTypeError,
)

__all__ = ['OAuth2Session', 'OAuth2Auth']


class OAuth2Auth(AuthBase, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""

    def ensure_active_token(self, **kwargs):
        if not self.token:
            raise MissingTokenError()

        if self.client and self.token.is_expired():
            refresh_token = self.token.get('refresh_token')
            client = self.client
            url = client.metadata.get('token_endpoint')
            if refresh_token and url:
                return client.refresh_token(url, refresh_token=refresh_token, **kwargs)
            elif client.metadata.get('grant_type') == 'client_credentials':
                return client.fetch_token(grant_type='client_credentials', **kwargs)
            else:
                raise InvalidTokenError()

    def __call__(self, req):
        self.ensure_active_token()
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
    :param authorization_endpoint: URL of the authorization server's
        authorization endpoint.
    :param token_endpoint: URL of the authorization server's token endpoint.
    :param token_endpoint_auth_method: client authentication method for
        token endpoint.
    :param revocation_endpoint: URL of the authorization server's OAuth 2.0
        revocation endpoint.
    :param revocation_endpoint_auth_method: client authentication method for
        revocation endpoint.
    :param scope: Scope that you needed to access user resources.
    :param redirect_uri: Redirect URI you registered as callback.
    :param token: A dict of token attributes such as ``access_token``,
        ``token_type`` and ``expires_at``.
    :param token_placement: The place to put token in HTTP request. Available
        values: "header", "body", "uri".
    :param token_updater: A function for you to update token. It accept a
        :class:`OAuth2Token` as parameter.
    """
    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    SESSION_REQUEST_PARAMS = (
        'allow_redirects', 'timeout', 'cookies', 'files',
        'proxies', 'hooks', 'stream', 'verify', 'cert', 'json'
    )

    def __init__(self, client_id=None, client_secret=None,
                 token_endpoint_auth_method=None,
                 revocation_endpoint_auth_method=None,
                 scope=None, redirect_uri=None,
                 token=None, token_placement='header', token_updater=None, **kwargs):

        Session.__init__(self)
        OAuth2Client.__init__(
            self, session=self,
            client_id=client_id, client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope, redirect_uri=redirect_uri,
            token=token, token_placement=token_placement,
            token_updater=token_updater, **kwargs
        )

    def register_client_auth_method(self, func):
        """Extend client authenticate for token endpoint.

        :param func: a function to sign the request
        """
        self.client_auth_class.register_auth_method(self.token_endpoint_auth_method, func)

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
