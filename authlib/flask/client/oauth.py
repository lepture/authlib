import uuid
import warnings
import functools
from flask import request, redirect, session
from werkzeug.local import LocalProxy
from authlib.client.errors import OAuthException
from authlib.client.client import OAuthClient
from authlib.common.compat import deprecate
from ..cache import Cache

__all__ = ['OAuth', 'RemoteApp']


class OAuth(object):
    """Registry for oauth clients.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app)

    You can also pass the instance of Flask later::

        oauth = OAuth()
        oauth.init_app(app)

    :param app: Flask application instance
    :param fetch_token: a shared function to get current user's token
    :param update_token: a share function to update current user's token
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
        """Init app with Flask instance."""
        self.app = app
        if 'OAUTH_CLIENT_CACHE_TYPE' in app.config:
            self.cache = Cache(app, config_prefix='OAUTH_CLIENT')

        if fetch_token:
            self.fetch_token = fetch_token
        if update_token:
            self.update_token = update_token

        app.extensions = getattr(app, 'extensions', {})
        app.extensions['authlib.flask.client'] = self

    def create_client(self, name):
        if not self.app:
            raise RuntimeError('OAuth is not init with Flask app.')

        if name in self._clients:
            return self._clients[name]

        keys = (
            'client_id', 'client_secret',
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

        if not kwargs['client_id']:
            conf_key = '{}_client_key'.format(name).upper()
            kwargs['client_id'] = self.app.config.get(conf_key, None)
            deprecate(
                'Use "{}" instead of "{}".'.format(
                    conf_key.replace('CLIENT_KEY', 'CLIENT_ID'),
                    conf_key
                )
            )

        fetch_token = kwargs.pop('fetch_token', None)
        if fetch_token is None and self.fetch_token:
            fetch_token = functools.partial(self.fetch_token, name=name)

        update_token = kwargs.pop('update_token', None)
        if update_token is None and self.update_token:
            update_token = functools.partial(self.update_token, name=name)

        client = RemoteApp(
            name, self.cache, fetch_token, update_token, **kwargs
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

            oauth.register('twitter', client_id='', ...)
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

        super(RemoteApp, self).__init__(*args, **kwargs)

        if self.client_kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = update_token

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
        return self._fetch_token()

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

    def authorize_access_token(self, **kwargs):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._get_request_token()
            params = request.args.to_dict(flat=True)
        else:
            request_token = None
            params = {}

            # verify state
            state_key = '_{}_state_'.format(self.name)
            state = session.pop(state_key, None)
            if state != request.args.get('state'):
                raise OAuthException(
                    'State not equal in request and response.')
            if state:
                params['state'] = state

        cb_key = '_{}_callback_'.format(self.name)
        callback_uri = session.pop(cb_key, None)
        params.update(kwargs)
        return self.fetch_access_token(
            callback_uri,
            request_token,
            **params
        )
