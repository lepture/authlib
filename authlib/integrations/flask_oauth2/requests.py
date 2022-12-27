from flask.wrappers import Request
from authlib.oauth2.rfc6749 import OAuth2Request, JsonRequest


class FlaskOAuth2Request(OAuth2Request):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.form

    @property
    def data(self):
        return self._request.values


class FlaskJsonRequest(JsonRequest):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, None, request.headers)
        self._request = request

    @property
    def data(self):
        return self._request.get_json()
