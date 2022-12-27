from django.http import HttpRequest
from django.utils.functional import cached_property
from authlib.common.encoding import json_loads
from authlib.oauth2.rfc6749 import OAuth2Request, JsonRequest


class DjangoOAuth2Request(OAuth2Request):
    def __init__(self, request: HttpRequest):
        super().__init__(request.method, request.build_absolute_uri(), None, request.headers)
        self._request = request

    @property
    def args(self):
        return self._request.GET

    @property
    def form(self):
        return self._request.POST

    @cached_property
    def data(self):
        data = {}
        data.update(self._request.GET.dict())
        data.update(self._request.POST.dict())
        return data


class DjangoJsonRequest(JsonRequest):
    def __init__(self, request: HttpRequest):
        super().__init__(request.method, request.build_absolute_uri(), None, request.headers)
        self._request = request

    @cached_property
    def data(self):
        return json_loads(self._request.body)
