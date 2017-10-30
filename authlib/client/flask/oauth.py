from ..client import OAuthClient

__all__ = ['OAuth']


class OAuth(object):
    """Registry for oauth clients.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app)
    """

    def __init__(self, app=None):
        self._registry = {}
        self._clients = {}

        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::

            oauth = OAuth()
            oauth.init_app(app)
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['authlib.client.flask'] = self

    def create_client(self, name):
        if not self.app:
            raise RuntimeError('OAuth is not init with Flask app.')

        if name in self._clients:
            return self._clients[name]

        keys = (
            'client_key', 'client_secret',
            'request_token_url', 'request_token_params',
            'access_token_url', 'access_token_params',
            'refresh_token_url', 'authorize_url', 'api_base_url'
        )

        kwargs = self._registry[name]
        compliance_fix = kwargs.pop('compliance_fix', None)
        for k in keys:
            if k not in kwargs:
                conf_key = '{}_{}'.format(name, k).upper()
                v = self.app.config.get(conf_key, None)
                kwargs[k] = v

        client = OAuthClient(**kwargs)
        if compliance_fix:
            client.compliance_fix = compliance_fix

        self._clients[name] = client
        return client

    def register(self, name, **kwargs):
        """Registers a new remote application.

        :param name: the name of the remote application

        Find more parameters from :class:`OAuthClient`.
        """
        self._registry[name] = kwargs
        if self.app:
            return self.create_client(name)

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if key in self._registry:
                return self.create_client(key)
            raise AttributeError('No such client: %s' % key)
