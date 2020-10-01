import asyncio
import typing
from httpx import AsyncClient, Auth, Client, Request, Response
try:
    from httpx._config import UNSET
except ImportError:
    UNSET = None
from authlib.common.urls import url_decode
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.auth import ClientAuth, TokenAuth
from .utils import HTTPX_CLIENT_KWARGS
from ..base_client import (
    OAuthError,
    InvalidTokenError,
    MissingTokenError,
    UnsupportedTokenTypeError,
)

__all__ = [
    'OAuth2Auth', 'OAuth2ClientAuth',
    'AsyncOAuth2Client',
]


class OAuth2Auth(Auth, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""
    requires_request_body = True

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        try:
            url, headers, body = self.prepare(
                str(request.url), request.headers, request.content)
            yield Request(method=request.method, url=url, headers=headers, data=body)
        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)


class OAuth2ClientAuth(Auth, ClientAuth):
    requires_request_body = True

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        url, headers, body = self.prepare(
            request.method, str(request.url), request.headers, request.content)
        yield Request(method=request.method, url=url, headers=headers, data=body)


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

        # We use a "reverse" Event to synchronize coroutines to prevent
        # multiple concurrent attempts to refresh the same token
        self._token_refresh_event = asyncio.Event()
        self._token_refresh_event.set()

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
        if not withhold_token and auth is UNSET:
            if not self.token:
                raise MissingTokenError()

            if self.token.is_expired():
                await self.ensure_active_token()

            auth = self.token_auth

        return await super(AsyncOAuth2Client, self).request(
            method, url, auth=auth, **kwargs)

    async def ensure_active_token(self):
        if self._token_refresh_event.is_set():
            # Unset the event so other coroutines don't try to update the token
            self._token_refresh_event.clear()
            refresh_token = self.token.get('refresh_token')
            url = self.metadata.get('token_endpoint')
            if refresh_token and url:
                await self.refresh_token(url, refresh_token=refresh_token)
            elif self.metadata.get('grant_type') == 'client_credentials':
                access_token = self.token['access_token']
                token = await self.fetch_token(url, grant_type='client_credentials')
                if self.update_token:
                    await self.update_token(token, access_token=access_token)
            else:
                raise InvalidTokenError()
            # Notify coroutines that token is refreshed
            self._token_refresh_event.set()
            return
        await self._token_refresh_event.wait() # wait until the token is ready

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

    def _http_post(self, url, body=None, auth=None, headers=None, **kwargs):
        return self.post(
            url, data=dict(url_decode(body)),
            headers=headers, auth=auth, **kwargs)


class OAuth2Client(_OAuth2Client, Client):
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

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    def request(self, method, url, withhold_token=False, auth=None, **kwargs):
        if not withhold_token and auth is UNSET:
            if not self.token:
                raise MissingTokenError()

            if self.token.is_expired():
                self.ensure_active_token()

            auth = self.token_auth

        return super(OAuth2Client, self).request(
            method, url, auth=auth, **kwargs)

    def ensure_active_token(self):
        refresh_token = self.token.get('refresh_token')
        url = self.metadata.get('token_endpoint')
        if refresh_token and url:
            self.refresh_token(url, refresh_token=refresh_token)
        elif self.metadata.get('grant_type') == 'client_credentials':
            access_token = self.token['access_token']
            token = self.fetch_token(url, grant_type='client_credentials')
            if self.update_token:
                self.update_token(token, access_token=access_token)
        else:
            raise InvalidTokenError()
