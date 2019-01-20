from yarl import URL
from aiohttp import ClientRequest
from authlib.common.urls import url_decode
from authlib.oauth1.client import OAuth1Client
from authlib.oauth2.client import OAuth2Client


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


class AsyncOAuth1Client(OAuth1Client):
    """The OAuth 1.0 Client for ``aiohttp.ClientSession``. Here
    is how it works::

        from aiohttp import ClientSession

        async with ClientSession(request_class=OAuth1ClientRequest) as session:
            client = OAuth1AsyncClient(session, client_id, client_secret, ...)
    """
    async def _fetch_token(self, url, **kwargs):
        async with self.post(url, **kwargs) as resp:
            text = await resp.text()
            token = self.parse_response_token(resp.status, text)
            self.token = token
            return token

    def get(self, url, **kwargs):
        return self.session.get(url, auth=self.auth, **kwargs)

    def options(self, url, **kwargs):
        return self.session.options(url, auth=self.auth, **kwargs)

    def head(self, url, **kwargs):
        return self.session.head(url, auth=self.auth, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, auth=self.auth, **kwargs)

    def put(self, url, **kwargs):
        return self.session.put(url, auth=self.auth, **kwargs)

    def patch(self, url, **kwargs):
        return self.session.patch(url, auth=self.auth, **kwargs)

    def delete(self, url, **kwargs):
        return self.session.delete(url, auth=self.auth, **kwargs)


class AsyncOAuth2Client(OAuth2Client):
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

    async def _wrap_request(self, method, url, **kwargs):
        await self.token_auth.auto_refresh_token()
        func = getattr(self.session, method)
        return func(url, auth=self.token_auth, **kwargs)

    def get(self, url, **kwargs):
        return self._wrap_request('get', url, **kwargs)

    def options(self, url, **kwargs):
        return self._wrap_request('options', url, **kwargs)

    def head(self, url, **kwargs):
        return self._wrap_request('head', url, **kwargs)

    def post(self, url, **kwargs):
        return self._wrap_request('post', url, **kwargs)

    def put(self, url, **kwargs):
        return self._wrap_request('put', url, **kwargs)

    def patch(self, url, **kwargs):
        return self._wrap_request('patch', url, **kwargs)

    def delete(self, url, **kwargs):
        return self._wrap_request('delete', url, **kwargs)
