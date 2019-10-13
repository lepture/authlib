import typing
from httpx import Client, AsyncClient
from httpx.middleware.base import BaseMiddleware
from httpx.models import (
    AsyncRequest,
    AsyncResponse,
)
from authlib.common.urls import url_decode
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.auth import ClientAuth, TokenAuth
from .utils import HTTPX_CLIENT_KWARGS, auth_call
from .._client import (
    OAuthError,
    InvalidTokenError,
    MissingTokenError,
    UnsupportedTokenTypeError,
)

__all__ = [
    'OAuth2Auth', 'OAuth2ClientAuth',
    'OAuth2Client', 'AsyncOAuth2Client',
]


class OAuth2Auth(BaseMiddleware, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""

    async def __call__(
        self, request: AsyncRequest, get_response: typing.Callable
    ) -> AsyncResponse:
        try:
            return await auth_call(self, request, get_response, False)
        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)


class OAuth2ClientAuth(BaseMiddleware, ClientAuth):
    async def __call__(
        self, request: AsyncRequest, get_response: typing.Callable
    ) -> AsyncResponse:
        return await auth_call(self, request, get_response)


class OAuth2Client(_OAuth2Client, Client):
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
    :param update_token: A function for you to update token. It accept a
        :class:`OAuth2Token` as parameter.
    """
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth

    def __init__(self, client_id=None, client_secret=None,
                 token_endpoint_auth_method=None,
                 revocation_endpoint_auth_method=None,
                 scope=None, redirect_uri=None,
                 token=None, token_placement='header',
                 update_token=None, **kwargs):

        # extract httpx.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        Client.__init__(self, **client_kwargs)

        _OAuth2Client.__init__(
            self, session=self,
            client_id=client_id, client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope, redirect_uri=redirect_uri,
            token=token, token_placement=token_placement,
            update_token=update_token, **kwargs
        )

    def request(self, method, url, withhold_token=False, auth=None, **kwargs):
        """Send request with auto refresh token feature (if available)."""
        if not withhold_token and auth is None:
            if not self.token:
                raise MissingTokenError()

            if self.token.is_expired():
                self.ensure_active_token(**kwargs)

            auth = self.token_auth
        return super(OAuth2Client, self).request(
            method, url, auth=auth, **kwargs)

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    def ensure_active_token(self, **kwargs):
        refresh_token = self.token.get('refresh_token')
        url = self.metadata.get('token_endpoint')
        if refresh_token and url:
            self.refresh_token(url, refresh_token=refresh_token, **kwargs)
        elif self.metadata.get('grant_type') == 'client_credentials':
            access_token = self.token['access_token']
            token = self.fetch_token(url, grant_type='client_credentials', **kwargs)
            if self.update_token:
                self.update_token(token, access_token=access_token)
        else:
            raise InvalidTokenError()


class AsyncOAuth2Client(_OAuth2Client, AsyncClient):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth

    def __init__(self, client_id=None, client_secret=None,
                 token_endpoint_auth_method=None,
                 revocation_endpoint_auth_method=None,
                 scope=None, redirect_uri=None,
                 token=None, token_placement='header',
                 update_token=None, **kwargs):

        # extract httpx.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        AsyncClient.__init__(self, **client_kwargs)

        _OAuth2Client.__init__(
            self, session=None,
            client_id=client_id, client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope, redirect_uri=redirect_uri,
            token=token, token_placement=token_placement,
            update_token=update_token, **kwargs
        )

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    async def request(self, method, url, withhold_token=False, auth=None, **kwargs):
        if not withhold_token and auth is None:
            if not self.token:
                raise MissingTokenError()

            if self.token.is_expired():
                await self.ensure_active_token(**kwargs)

            auth = self.token_auth

        return await super(AsyncOAuth2Client, self).request(
            method, url, auth=auth, **kwargs)

    async def ensure_active_token(self, **kwargs):
        refresh_token = self.token.get('refresh_token')
        url = self.metadata.get('token_endpoint')
        if refresh_token and url:
            await self.refresh_token(url, refresh_token=refresh_token, **kwargs)
        elif self.metadata.get('grant_type') == 'client_credentials':
            access_token = self.token['access_token']
            token = await self.fetch_token(url, grant_type='client_credentials', **kwargs)
            if self.update_token:
                await self.update_token(token, access_token=access_token)
        else:
            raise InvalidTokenError()

    async def _fetch_token(self, url, body='', headers=None, auth=None,
                           method='POST', **kwargs):
        if method.upper() == 'POST':
            resp = await self.post(
                url, data=dict(url_decode(body)), headers=headers,
                auth=auth, **kwargs)
        else:
            if '?' in url:
                url = '&'.join([url, body])
            else:
                url = '?'.join([url, body])
            resp = await self.get(url, headers=headers, auth=auth, **kwargs)

        for hook in self.compliance_hook['access_token_response']:
            resp = hook(resp)

        return self.parse_response_token(resp.json())

    async def _refresh_token(self, url, refresh_token=None, body='',
                             headers=None, auth=None, **kwargs):
        resp = await self.post(
            url, data=dict(url_decode(body)), headers=headers,
            auth=auth, **kwargs)

        for hook in self.compliance_hook['refresh_token_response']:
            resp = hook(resp)

        token = self.parse_response_token(resp.json())
        if 'refresh_token' not in token:
            self.token['refresh_token'] = refresh_token

        if self.update_token:
            await self.update_token(self.token, refresh_token=refresh_token)

        return self.token

    def _revoke_token(self, url, body=None, auth=None, headers=None, **kwargs):
        return self.post(
            url, data=dict(url_decode(body)),
            headers=headers, auth=auth, **kwargs)
