import uuid
from flask import request, redirect, session
from authlib.common.flask import Cache
from ..errors import OAuthException
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
        self.cache = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::

            oauth = OAuth()
            oauth.init_app(app)
        """
        self.app = app
        self.cache = Cache(app)
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
            'refresh_token_url', 'authorize_url',
            'api_base_url', 'client_kwargs',
        )

        kwargs = self._registry[name]
        compliance_fix = kwargs.pop('compliance_fix', None)
        for k in keys:
            if k not in kwargs:
                conf_key = '{}_{}'.format(name, k).upper()
                v = self.app.config.get(conf_key, None)
                kwargs[k] = v

        client = RemoteApp(name, self.cache, **kwargs)
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


class TokenMixin(object):
    @classmethod
    def fetch_token(cls, name):
        raise NotImplementedError()

    @classmethod
    def update_token(cls, name, token):
        raise NotImplementedError()


class RemoteApp(OAuthClient):
    token_model = TokenMixin

    def __init__(self, name, cache=None, *args, **kwargs):
        self.name = name
        self.cache = cache
        fetch_user = kwargs.pop('fetch_user', None)
        super(RemoteApp, self).__init__(*args, **kwargs)

        if fetch_user:
            self.fetch_user = lambda: fetch_user(self)
        else:
            self.fetch_user = lambda: None

        self.register_hook('authorize_redirect', self.redirect_hook)
        self.register_hook('access_token_getter', self.access_token_getter)

        if self.request_token_url:
            self.register_hook(
                'request_token_getter',
                self.request_token_getter
            )
            self.register_hook(
                'request_token_setter',
                self.request_token_setter
            )
        elif self.client_kwargs.get('auto_refresh_url'):
            self.client_kwargs['token_updater'] = self.token_updater

    def redirect_hook(self, uri, callback_uri=None, state=None):
        if callback_uri:
            key = '_{}_callback_'.format(self.name)
            session[key] = callback_uri
        if state:
            key = '_{}_state_'.format(self.name)
            session[key] = state
        return redirect(uri)

    def access_token_getter(self):
        return self.token_model.fetch_token(self.name)

    def request_token_getter(self):
        key = '_{}_req_token_'.format(self.name)
        sid = session.pop(key, None)
        if not sid:
            raise OAuthException('Missing request token')

        token = self.cache.get(sid)
        self.cache.delete(sid)
        return token

    def request_token_setter(self, token):
        key = '_{}_req_token_'.format(self.name)
        sid = uuid.uuid4().hex
        session[key] = sid
        self.cache.set(sid, token)

    def token_updater(self, token):
        self.token_model.update_token(self.name, token)

    def authorize_response(self):
        if not self.request_token_url:
            state_key = '_{}_state_'.format(self.name)
            state = session.pop(state_key, None)
            if state != request.args.get('state'):
                raise OAuthException(
                    'State not equal in request and response.')

        cb_key = '_{}_callback_'.format(self.name)
        callback_uri = session.pop(cb_key, None)
        params = request.args.to_dict(flat=True)
        token = self.authorize_access_token(callback_uri, **params)
        return token
