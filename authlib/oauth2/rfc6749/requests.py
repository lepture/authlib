from collections import defaultdict

from .errors import InsecureTransportError


class OAuth2Request:
    def __init__(self, method: str, uri: str, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        raise NotImplementedError()

    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        raise NotImplementedError()

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get("client_id")

    @property
    def response_type(self) -> str:
        rt = self.data.get("response_type")
        if rt and " " in rt:
            # sort multiple response types
            return " ".join(sorted(rt.split()))
        return rt

    @property
    def grant_type(self) -> str:
        return self.form.get("grant_type")

    @property
    def redirect_uri(self):
        return self.data.get("redirect_uri")

    @property
    def scope(self) -> str:
        return self.data.get("scope")

    @property
    def state(self):
        return self.data.get("state")


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}

    @property
    def data(self):
        raise NotImplementedError()
