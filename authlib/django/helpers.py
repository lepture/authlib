from collections import MutableMapping as DictMixin
from authlib.common.encoding import to_unicode


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
