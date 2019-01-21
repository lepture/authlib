from yarl import URL
from aiohttp import ClientRequest
from authlib.common.urls import url_decode
from authlib.oauth1.client import OAuth1Client
from authlib.oauth2.client import OAuth2Client
from .errors import OAuthError


class OAuthRequest(ClientRequest):
    def __init__(self, *args, **kwargs):
        auth = kwargs.pop('auth', None)
        data = kwargs.get('data')
        super(OAuthRequest, self).__init__(*args, **kwargs)
        self.update_oauth_auth(auth, data)

    def update_oauth_auth(self, auth, data):
        if auth is None:
            return

        url, headers, body = auth.prepare(
            self.method, str(self.url), self.headers, data)
        self.url = URL(url)
        self.update_headers(headers)
        if body:
            self.update_body_from_data(body)


class AsyncClientMixin(object):
    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    def _request(self, method, url, **kwargs):
        raise NotImplementedError()

    def get(self, url, **kwargs):
        return self._request('GET', url, **kwargs)

    def options(self, url, **kwargs):
        return self._request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):
        return self._request('HEAD', url, **kwargs)

    def post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self._request('PUT', url, **kwargs)

    def patch(self, url, **kwargs):
        return self._request('PATCH', url, **kwargs)

    def delete(self, url, **kwargs):
        return self._request('DELETE', url, **kwargs)


class AsyncOAuth1Client(AsyncClientMixin, OAuth1Client):
    """The OAuth 1.0 Client for ``aiohttp.ClientSession``. Here
    is how it works::

        from aiohttp import ClientSession

        async with ClientSession(request_class=OAuthRequest) as session:
            client = AsyncOAuth1Client(session, client_id, client_secret, ...)
    """
    async def _fetch_token(self, url, **kwargs):
        async with self.post(url, **kwargs) as resp:
            text = await resp.text()
            token = self.parse_response_token(resp.status, text)
            self.token = token
            return token

    def _request(self, method, url, **kwargs):
        return self.session.request(method, url, auth=self.auth, **kwargs)


class AsyncOAuth2Client(AsyncClientMixin, OAuth2Client):
    SESSION_REQUEST_PARAMS = (
        'timeout', 'allow_redirects', 'max_redirects',
        'expect100', 'read_until_eof',
        'json', 'cookies', 'skip_auto_headers', 'compress',
        'chunked', 'raise_for_status', 'proxy', 'proxy_auth',
        'verify_ssl', 'fingerprint', 'ssl_context', 'ssl',
        'proxy_headers', 'trace_request_ctx',
    )

    async def _fetch_token(self, url, body='', headers=None, auth=None,
                           method='POST', **kwargs):
        if method.upper() == 'POST':
            async with self.session.post(
                    url, data=dict(url_decode(body)), headers=headers,
                    auth=auth, **kwargs) as resp:
                token = await self._parse_token(resp, 'access_token_response')
                return self.parse_response_token(token)
        else:
            async with self.session.get(
                    url, params=dict(url_decode(body)), headers=headers,
                    auth=auth, **kwargs) as resp:
                token = await self._parse_token(resp, 'access_token_response')
                return self.parse_response_token(token)

    async def _refresh_token(self, url, refresh_token=None, body='', headers=None,
                             auth=None, **kwargs):
        async with self.session.post(
                url, data=dict(url_decode(body)), headers=headers,
                auth=auth, **kwargs) as resp:
            token = await self._parse_token(resp, 'refresh_token_response')
            if 'refresh_token' not in token:
                self.token['refresh_token'] = refresh_token

            if callable(self.token_updater):
                await self.token_updater(self.token)

            return self.token

    async def _parse_token(self, resp, hook_type):
        for hook in self.compliance_hook[hook_type]:
            resp = await hook(resp)
        token = await resp.json()
        return token

    async def _request(self, method, url, **kwargs):
        await self.token_auth.ensure_refresh_token()
        return self.session.request(
            method, url, auth=self.token_auth, **kwargs)
