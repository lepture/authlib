import uuid
from flask import request, redirect, session
from werkzeug.local import LocalProxy
from authlib.common.flask import Cache
from ..errors import OAuthException
from ..client import OAuthClient

__all__ = ['OAuth', 'RemoteApp']


class OAuth(object):
    """Registry for oauth clients.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app)
    """

    def __init__(self, app=None, fetch_token=None, update_token=None):
        self._registry = {}
        self._clients = {}

        self.app = app
        self.fetch_token = fetch_token
        self.update_token = update_token
        self.cache = None
        if app:
            self.init_app(app)

    def init_app(self, app, fetch_token=None, update_token=None):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::

            oauth = OAuth()
            oauth.init_app(app)
        """
        self.app = app
        if 'OAUTH_CLIENT_CACHE_TYPE' in app.config:
            self.cache = Cache(app, config_prefix='OAUTH_CLIENT')

        if fetch_token:
            self.fetch_token = fetch_token
        if update_token:
            self.update_token = update_token

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

        client = RemoteApp(
            name, self.cache, self.fetch_token,
            self.update_token, **kwargs
        )
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
        return LocalProxy(lambda: self.create_client(name))

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if key in self._registry:
                return self.create_client(key)
            raise AttributeError('No such client: %s' % key)


class RemoteApp(OAuthClient):
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, name, cache=None, fetch_token=None, update_token=None,
                 *args, **kwargs):
        self.name = name
        self.cache = cache
        self._fetch_token = fetch_token
        self._update_token = update_token

        super(RemoteApp, self).__init__(*args, **kwargs)

        if self.client_kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = lambda token:\
                self._update_token(name, token)

    def _get_request_token(self):
        key = '_{}_req_token_'.format(self.name)
        sid = session.pop(key, None)
        if not sid:
            return None

        token = self.cache.get(sid)
        self.cache.delete(sid)
        return token

    def _save_request_token(self, token):
        key = '_{}_req_token_'.format(self.name)
        sid = uuid.uuid4().hex
        session[key] = sid
        self.cache.set(sid, token, timeout=600)

    def get_token(self):
        return self._fetch_token(self.name)

    def authorize_redirect(self, callback_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param callback_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        if callback_uri:
            key = '_{}_callback_'.format(self.name)
            session[key] = callback_uri

        if self.request_token_url:
            save_request_token = self._save_request_token
        else:
            save_request_token = None

        uri, state = self.generate_authorize_redirect(
            callback_uri,
            save_request_token,
            **kwargs
        )
        if state:
            key = '_{}_state_'.format(self.name)
            session[key] = state
        return redirect(uri)

    def authorize_access_token(self):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._get_request_token()
        else:
            request_token = None
            state_key = '_{}_state_'.format(self.name)
            state = session.pop(state_key, None)
            if state != request.args.get('state'):
                raise OAuthException(
                    'State not equal in request and response.')

        cb_key = '_{}_callback_'.format(self.name)
        callback_uri = session.pop(cb_key, None)
        params = request.args.to_dict(flat=True)
        return self.fetch_access_token(
            callback_uri,
            request_token,
            **params
        )
