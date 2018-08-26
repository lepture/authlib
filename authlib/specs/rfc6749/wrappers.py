import time
from authlib.common.urls import (
    urlparse, extract_params, url_decode,
)
from .errors import InsecureTransportError


class OAuth2Token(dict):
    def __init__(self, params):
        if 'expires_at' in params:
            params['expires_at'] = int(params['expires_at'])
        elif 'expires_in' in params:
            params['expires_at'] = int(time.time()) + \
                                   int(params['expires_in'])
        super(OAuth2Token, self).__init__(params)

    def is_expired(self):
        expires_at = self.get('expires_at')
        if not expires_at:
            return None
        return expires_at < time.time()

    @classmethod
    def from_dict(cls, token):
        if isinstance(token, dict) and not isinstance(token, cls):
            token = cls(token)
        return token


class OAuth2Request(object):
    def __init__(self, method, uri, body=None, headers=None):
        InsecureTransportError.check(uri)
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers or {}

        self.query = urlparse.urlparse(uri).query
        self.query_params = url_decode(self.query)
        self.body_params = extract_params(body) or []

        params = {}
        if self.query_params:
            params.update(dict(self.query_params))
        if self.body_params:
            params.update(dict(self.body_params))
        self.data = params

        self.user = None
        #: authorization_code or token model instance
        self.credential = None
        self.client = None

    def __getattr__(self, key):
        keys = {
            'client_id', 'code', 'redirect_uri', 'scope', 'state',
            'response_type', 'grant_type'
        }
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in keys:
                return self.data.get(key)
            raise error


class TokenRequest(object):
    def __init__(self, method, uri, body=None, headers=None):
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers or {}
