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

    def __init__(self, app=None, token_model=None):
        self._registry = {}
        self._clients = {}

        self.app = app
        self.cache = None
        if token_model is None:
            token_model = TokenMixin
        self.token_model = token_model
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::

            oauth = OAuth()
            oauth.init_app(app)
        """
        self.app = app
        self.cache = Cache(app, config_prefix='OAUTH_CLIENT')
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
            'refresh_token_url', 'refresh_token_params',
            'authorize_url', 'api_base_url', 'client_kwargs',
        )

        kwargs = self._registry[name]
        compliance_fix = kwargs.pop('compliance_fix', None)
        for k in keys:
            if k not in kwargs:
                conf_key = '{}_{}'.format(name, k).upper()
                v = self.app.config.get(conf_key, None)
                kwargs[k] = v

        client = RemoteApp(name, self.cache, self.token_model, **kwargs)
        if compliance_fix:
            client.compliance_fix = compliance_fix

        self._clients[name] = client
        return client

    def register(self, name, **kwargs):
        """Registers a new remote application.

        :param name: Name of the remote application.
        :param kwargs: Parameters for :class:`RemoteApp`.

        Find parameters from :class:`~authlib.client.OAuthClient`.
        When a remote app is registered, it can be accessed with
        *named* attribute::

            oauth.register('twitter', client_key='', ...)
            oauth.twitter.get('timeline')
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
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, name, cache=None, token_model=None, *args, **kwargs):
        self.name = name
        self.cache = cache

        if token_model is None:
            token_model = TokenMixin
        self.token_model = token_model
        super(RemoteApp, self).__init__(*args, **kwargs)

        self.register_hook('authorize_redirect', self._redirect_hook)
        self.register_hook('access_token_getter', self._access_token_getter)

        if self.request_token_url:
            self.register_hook(
                'request_token_getter',
                self._request_token_getter
            )
            self.register_hook(
                'request_token_setter',
                self._request_token_setter
            )
        elif self.client_kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = lambda token:\
                token_model.update_token(name, token)

    def _redirect_hook(self, uri, callback_uri=None, state=None):
        if callback_uri:
            key = '_{}_callback_'.format(self.name)
            session[key] = callback_uri
        if state:
            key = '_{}_state_'.format(self.name)
            session[key] = state
        return redirect(uri)

    def _access_token_getter(self):
        return self.token_model.fetch_token(self.name)

    def _request_token_getter(self):
        key = '_{}_req_token_'.format(self.name)
        sid = session.pop(key, None)
        if not sid:
            raise OAuthException('Missing request token')

        token = self.cache.get(sid)
        self.cache.delete(sid)
        return token

    def _request_token_setter(self, token):
        key = '_{}_req_token_'.format(self.name)
        sid = uuid.uuid4().hex
        session[key] = sid
        self.cache.set(sid, token)

    def authorize_access_token(self):
        """Authorize access token."""
        if not self.request_token_url:
            state_key = '_{}_state_'.format(self.name)
            state = session.pop(state_key, None)
            if state != request.args.get('state'):
                raise OAuthException(
                    'State not equal in request and response.')

        cb_key = '_{}_callback_'.format(self.name)
        callback_uri = session.pop(cb_key, None)
        params = request.args.to_dict(flat=True)
        token = self.fetch_access_token(callback_uri, **params)
        return token
