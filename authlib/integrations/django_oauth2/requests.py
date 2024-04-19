from collections import defaultdict

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

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self.args:
            values[k].extend(self.args.getlist(k))
        for k in self.form:
            values[k].extend(self.form.getlist(k))
        return values


class DjangoJsonRequest(JsonRequest):
    def __init__(self, request: HttpRequest):
        super().__init__(request.method, request.build_absolute_uri(), None, request.headers)
        self._request = request

    @cached_property
    def data(self):
        return json_loads(self._request.body)
