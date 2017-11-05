from collections import namedtuple

# TODO: find common fields for user
User = namedtuple('User', ['id', 'name', 'email'])


class AppFactory(object):
    def __init__(self, name, config, doc):
        self.name = name
        self.config = config
        self.oauth = None
        self._client = None
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
            return self._client
        raise RuntimeError('App not `register_to` any oauth registry')

    def get(self, url, **kwargs):
        return self.client.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self.client.post(url, **kwargs)

    def put(self, url, **kwargs):
        return self.client.put(url, **kwargs)

    def delete(self, url, **kwargs):
        return self.client.delete(url, **kwargs)
