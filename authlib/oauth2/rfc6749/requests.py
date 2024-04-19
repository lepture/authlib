from collections import defaultdict
from typing import DefaultDict

from authlib.common.encoding import json_loads
from authlib.common.urls import urlparse, url_decode
from .errors import InsecureTransportError


class OAuth2Request:
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

        self._parsed_query = None

    @property
    def args(self):
        if self._parsed_query is None:
            self._parsed_query = url_decode(urlparse.urlparse(self.uri).query)
        return dict(self._parsed_query)

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
    def datalist(self) -> DefaultDict[str, list]:
        """ Return all the data in query parameters and the body of the request as a dictionary with all the values
        in lists. """
        if self._parsed_query is None:
            self._parsed_query = url_decode(urlparse.urlparse(self.uri).query)
        values = defaultdict(list)
        for k, v in self._parsed_query:
            values[k].append(v)
        for k, v in self.form.items():
            values[k].append(v)
        return values

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get('client_id')

    @property
    def response_type(self) -> str:
        rt = self.data.get('response_type')
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
        return self.data.get('state')


class JsonRequest:
    def __init__(self, method, uri, body=None, headers=None):
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers or {}

    @property
    def data(self):
        return json_loads(self.body)
