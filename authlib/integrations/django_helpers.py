try:
    from collections.abc import MutableMapping as DictMixin
except ImportError:
    from collections import MutableMapping as DictMixin
from authlib.common.encoding import to_unicode, json_loads


def create_oauth_request(request, request_cls, use_json=False):
    if isinstance(request, request_cls):
        return request

    if request.method == 'POST':
        if use_json:
            body = json_loads(request.body)
        else:
            body = request.POST.dict()
    else:
        body = None

    headers = parse_request_headers(request)
    url = request.get_raw_uri()
    return request_cls(request.method, url, body, headers)


def parse_request_headers(request):
    return WSGIHeaderDict(request.META)


class WSGIHeaderDict(DictMixin):
    CGI_KEYS = ('CONTENT_TYPE', 'CONTENT_LENGTH')

    def __init__(self, environ):
        self.environ = environ

    def keys(self):
        return [x for x in self]

    def _ekey(self, key):
        key = key.replace('-', '_').upper()
        if key in self.CGI_KEYS:
            return key
        return 'HTTP_' + key

    def __getitem__(self, key):
        return _unicode_value(self.environ[self._ekey(key)])

    def __delitem__(self, key):  # pragma: no cover
        raise ValueError('Can not delete item')

    def __setitem__(self, key, value):  # pragma: no cover
        raise ValueError('Can not set item')

    def __iter__(self):
        for key in self.environ:
            if key[:5] == 'HTTP_':
                yield _unify_key(key[5:])
            elif key in self.CGI_KEYS:
                yield _unify_key(key)

    def __len__(self):
        return len(self.keys())

    def __contains__(self, key):
        return self._ekey(key) in self.environ


def _unicode_value(value):
    return to_unicode(value, 'latin-1')


def _unify_key(key):
    return key.replace('_', '-').title()
