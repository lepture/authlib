from yarl import URL
from aiohttp import ClientRequest, ClientSession
from requests import Session
from authlib.oauth1 import OAuth1Client
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
    async def _fetch_token(self, url, body='', headers=None, auth=None,
                           method='POST', timeout=None, verify=True,
                           proxies=None, cert=None):
        if method.upper() == 'POST':
            resp = self.session.post(
                url, data=body, timeout=timeout,
                headers=headers, auth=auth, verify_ssl=verify, proxies=proxies,
                cert=cert)
        else:
            resp = self.session.get(
                url, params=dict(url_decode(body)), timeout=timeout,
                headers=headers, auth=auth, verify_ssl=verify, proxies=proxies,
                cert=cert)

        for hook in self.compliance_hook['access_token_response']:
            resp = hook(resp)

        return self.parse_response_token(resp.json())
