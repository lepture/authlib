from authlib.common.urls import urlparse, url_decode
from .errors import InsecureTransportError


class OAuth2Request(object):
    def __init__(self, method: str, uri: str, body=None, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        self.body = body
        #: HTTP headers
        self.headers = headers or {}

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None

    @property
    def query(self):
        return urlparse.urlparse(self.uri).query

    @property
    def args(self):
        return dict(url_decode(self.query))

    @property
    def form(self):
        return self.body or {}

    @property
    def data(self):
        data = {}
        data.update(self.args)
        data.update(self.form)
        return data

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        if self.method == 'GET':
            return self.args.get('client_id')
        return self.form.get('client_id')

    @property
    def response_type(self) -> str:
        rt = self.args.get('response_type')
        if rt and ' ' in rt:
            # sort multiple response types
            return ' '.join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> str:
        return self.form.get('grant_type')

    @property
    def redirect_uri(self):
        return self.data.get('redirect_uri')

    @property
    def scope(self) -> str:
        return self.data.get('scope')

    @property
    def state(self):
        return self.args.get('state')
