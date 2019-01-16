from yarl import URL
from typing import Any  # noqa
from aiohttp import ClientRequest
from authlib.oauth1 import AuthClient
from .oauth1_protocol import OAuth1Protocol, parse_response_token


class BaseRequest(ClientRequest):
    def __init__(self, *args, **kwargs):
        auth = kwargs.pop('auth', None)
        data = kwargs.get('data')
        super(BaseRequest, self).__init__(*args, **kwargs)
        self.update_oauth_auth(auth, data)

    def update_oauth_auth(self, auth, data):
        raise NotImplementedError()


class OAuth1AsyncRequest(BaseRequest):
    def update_oauth_auth(self, auth: AuthClient, data: Any=None):
        if auth is None:
            return

        url, headers, body = auth.prepare(
            self.method, str(self.url), data, self.headers)
        self.url = URL(url)
        self.update_headers(headers)
        if body:
            self.update_body_from_data(body)


class OAuth1AsyncClient(OAuth1Protocol):
    """The OAuth 1.0 Client for ``aiohttp.ClientSession``. Here
    is how it works::

        from aiohttp import ClientSession

        async with ClientSession(request_class=OAuth1ClientRequest) as session:
            client = OAuth1AsyncClient(session, client_id, client_secret, ...)
    """
    async def _fetch_token(self, url, **kwargs):
        async with self.post(url, **kwargs) as resp:
            text = await resp.text()
            token = parse_response_token(resp.status, text)
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
