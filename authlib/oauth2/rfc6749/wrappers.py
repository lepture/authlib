import time
from authlib.common.urls import urlparse, url_decode
from .errors import InsecureTransportError


class OAuth2Token(dict):
    def __init__(self, params):
        if params.get('expires_at'):
            params['expires_at'] = int(params['expires_at'])
        elif params.get('expires_in'):
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
        #: HTTP method
        self.method = method
        self.uri = uri
        self.body = body
        #: HTTP headers
        self.headers = headers or {}

        self.query = urlparse.urlparse(uri).query

        self.args = dict(url_decode(self.query))
        self.form = self.body or {}

        #: dict of query and body params
        data = {}
        data.update(self.args)
        data.update(self.form)
        self.data = data

        #: authenticate method
        self.auth_method = None
        #: authenticated user on this request
        self.user = None
        #: authorization_code or token model instance
        self.credential = None
        #: client which sending this request
        self.client = None

    @property
    def client_id(self):
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get('client_id')

    @property
    def response_type(self):
        return self.data.get('response_type')

    @property
    def grant_type(self):
        return self.data.get('grant_type')

    @property
    def redirect_uri(self):
        return self.data.get('redirect_uri')

    @property
    def scope(self):
        return self.data.get('scope')

    @property
    def state(self):
        return self.data.get('state')


class HttpRequest(object):
    def __init__(self, method, uri, data=None, headers=None):
        self.method = method
        self.uri = uri
        self.data = data
        self.headers = headers or {}
        self.user = None
