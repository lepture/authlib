import functools

__all__ = ['OAuth']


OAUTH_CLIENT_PARAMS = (
    'client_id', 'client_secret',
    'request_token_url', 'request_token_params',
    'access_token_url', 'access_token_params',
    'refresh_token_url', 'refresh_token_params',
    'authorize_url', 'authorize_params',
    'api_base_url', 'client_kwargs',
    'server_metadata_url',
)


class OAuth(object):
    """Registry for oauth clients.

    Create an instance for registry::

        oauth = OAuth()
    """
    AVAILABLE_CLIENTS = {}
    remote_app_class = None

    def __init__(self, fetch_token=None, update_token=None):
        self._registry = {}
        self._clients = {}
        self.fetch_token = fetch_token
        self.update_token = update_token
        self.oauth1_client_cls = None
        self.oauth2_client_cls = None
        if not self.AVAILABLE_CLIENTS:
            self.AVAILABLE_CLIENTS = _import_oauth_clients()

    def use_oauth_clients(self, name='requests'):
        """Choose the OAuth Clients to use. Supported clients are:

        * requests: using ``authlib.integrations.requests_client``
        * httpx: using ``authlib.integrations.httpx_client``

        By default, the OAuth registry will use ``requests``. Developers
        may switch to **httpx** with::

            oauth = OAuth()
            oauth.use_oauth_clients("httpx")
        """
        clients = self.AVAILABLE_CLIENTS[name]
        self.oauth1_client_cls = clients[0]
        self.oauth2_client_cls = clients[1]

    def create_client(self, name):
        """Create or get the given named OAuth client. For instance, the
        OAuth registry has ``.register`` a twitter client, developers may
        access the client with::

            client = oauth.create_client('twitter')

        :param: name: Name of the remote application
        :return: OAuth remote app
        """
        if name in self._clients:
            return self._clients[name]

        if name not in self._registry:
            return None

        overwrite, config = self._registry[name]
        client_cls = config.pop('client_cls', self.remote_app_class)
        if client_cls.OAUTH_APP_CONFIG:
            kwargs = client_cls.OAUTH_APP_CONFIG
            kwargs.update(config)
        else:
            kwargs = config
        kwargs = self.generate_client_kwargs(name, overwrite, **kwargs)
        client = client_cls(name, **kwargs)
        self._clients[name] = client
        return client

    def register(self, name, overwrite=False, **kwargs):
        """Registers a new remote application.

        :param name: Name of the remote application.
        :param overwrite: Overwrite existing config with framework settings.
        :param kwargs: Parameters for :class:`RemoteApp`.

        Find parameters for the given remote app class. When a remote app is
        registered, it can be accessed with *named* attribute::

            oauth.register('twitter', client_id='', ...)
            oauth.twitter.get('timeline')
        """
        if not self.oauth1_client_cls or not self.oauth2_client_cls:
            self.use_oauth_clients()

        self._registry[name] = (overwrite, kwargs)
        return self.create_client(name)

    def generate_client_kwargs(self, name, overwrite, **kwargs):
        fetch_token = kwargs.pop('fetch_token', None)
        update_token = kwargs.pop('update_token', None)

        config = self.load_config(name, OAUTH_CLIENT_PARAMS)
        if config:
            kwargs = _config_client(config, kwargs, overwrite)

        if not fetch_token and self.fetch_token:
            fetch_token = functools.partial(self.fetch_token, name)

        kwargs['fetch_token'] = fetch_token

        if kwargs.get('request_token_url'):
            kwargs['oauth1_client_cls'] = self.oauth1_client_cls
        else:
            if not update_token and self.update_token:
                update_token = functools.partial(self.update_token, name)

            kwargs['update_token'] = update_token
            kwargs['oauth2_client_cls'] = self.oauth2_client_cls
        return kwargs

    def load_config(self, name, params):
        raise NotImplementedError()

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if key in self._registry:
                return self.create_client(key)
            raise AttributeError('No such client: %s' % key)


def _config_client(config, kwargs, overwrite):
    for k in OAUTH_CLIENT_PARAMS:
        v = config.get(k, None)
        if k not in kwargs:
            kwargs[k] = v
        elif overwrite and v:
            if isinstance(kwargs[k], dict):
                kwargs[k].update(v)
            else:
                kwargs[k] = v
    return kwargs


def _import_oauth_clients():
    rv = {}
    try:
        from ..requests_client import OAuth1Session, OAuth2Session
        rv['requests'] = OAuth1Session, OAuth2Session
    except ImportError:
        pass

    try:
        from ..httpx_client import OAuth1Client, OAuth2Client
        rv['httpx'] = OAuth1Client, OAuth2Client
    except (ImportError, SyntaxError):
        pass
    return rv
