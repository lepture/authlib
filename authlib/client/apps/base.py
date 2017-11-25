import types
from collections import namedtuple

User = namedtuple('User', ['id', 'name', 'email', 'data'])


class AppFactory(object):
    def __init__(self, name, config, doc):
        self.name = name
        self.config = config
        self.oauth = None
        self._client = None
        self._patch = {}
        self.__doc__ = doc.lstrip()

    def register_to(self, oauth):
        oauth.register(self.name, **self.config)
        self.oauth = oauth

    @property
    def client(self):
        if self._client:
            return self._client
        if self.oauth:
            self._client = self.oauth.create_client(self.name)
            if self._patch:
                for name in self._patch:
                    _patch(self._client, self._patch[name], name)
            return self._client
        raise RuntimeError('App not `register_to` any oauth registry')

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            return object.__getattribute__(self.client, key)


def patch_method(instance, func, name=None):
    if name is None:
        name = func.__name__

    _patch(instance, func, name)
    instance._patch[name] = func


def _patch(instance, func, name):
    setattr(instance, name, types.MethodType(func, instance))
