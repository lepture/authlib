import uuid
import functools
from flask import request, redirect, session
from flask import _app_ctx_stack
from werkzeug.local import LocalProxy
from authlib.client.errors import OAuthException
from authlib.client.client import OAuthClient

__all__ = ['OAuth', 'RemoteApp']


class OAuth(object):
    """Registry for oauth clients.

    :param app: the app instance of Flask

    Create an instance with Flask::

        oauth = OAuth(app, cache=cache)

    You can also pass the instance of Flask later::

        oauth = OAuth()
        oauth.init_app(app, cache=cache)

    :param app: Flask application instance
    :param cache: A cache instance that has .get .set and .delete methods
    :param fetch_token: a shared function to get current user's token
    :param update_token: a share function to update current user's token
    """

    def __init__(self, app=None, cache=None,
                 fetch_token=None, update_token=None):
        self._registry = {}
        self._clients = {}

        self.app = app
        self.fetch_token = fetch_token
        self.update_token = update_token
        self.cache = cache
        if app:
            self.init_app(app)

    def init_app(self, app, cache=None, fetch_token=None, update_token=None):
        """Init app with Flask instance."""
        self.app = app
        if cache:
            self.cache = cache

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

        overwrite, kwargs = self._registry[name]
        compliance_fix = kwargs.pop('compliance_fix', None)
        client_cls = kwargs.pop('client_cls', RemoteApp)

        for k in keys:
            conf_key = '{}_{}'.format(name, k).upper()
            v = self.app.config.get(conf_key, None)
            if k not in kwargs:
                kwargs[k] = v
            elif overwrite and v:
                if isinstance(kwargs[k], dict):
                    kwargs[k].update(v)
                else:
                    kwargs[k] = v

        kwargs = self._generate_client_kwargs(name, kwargs)
        client = client_cls(name, **kwargs)
        if compliance_fix:
            client.compliance_fix = compliance_fix

        self._clients[name] = client
        return client

    def register(self, name, overwrite=False, **kwargs):
        """Registers a new remote application.

        :param name: Name of the remote application.
        :param overwrite: Overwrite existing config with Flask config.
        :param kwargs: Parameters for :class:`RemoteApp`.

        Find parameters from :class:`~authlib.client.OAuthClient`.
        When a remote app is registered, it can be accessed with
        *named* attribute::

            oauth.register('twitter', client_id='', ...)
            oauth.twitter.get('timeline')
        """
        self._registry[name] = (overwrite, kwargs)
        if self.app:
            return self.create_client(name)
        return LocalProxy(lambda: self.create_client(name))

    def _generate_client_kwargs(self, name, kwargs):
        fetch_token = kwargs.pop('fetch_token', None)
        if fetch_token is None and self.fetch_token:
            fetch_token = functools.partial(self.fetch_token, name=name)
        if fetch_token:
            kwargs['fetch_token'] = fetch_token

        if kwargs['request_token_url']:
            # for OAuth 1
            cache = self.cache
            if not kwargs.get('fetch_request_token') and cache:
                def fetch_request_token():
                    key = '_{}_req_token_'.format(name)
                    sid = session.pop(key, None)
                    if not sid:
                        return None

                    token = cache.get(sid)
                    cache.delete(sid)
                    return token

                kwargs['fetch_request_token'] = fetch_request_token

            if not kwargs.get('save_request_token') and cache:
                def save_request_token(token):
                    key = '_{}_req_token_'.format(name)
                    sid = uuid.uuid4().hex
                    session[key] = sid
                    cache.set(sid, token, timeout=600)

                kwargs['save_request_token'] = save_request_token
        else:
            # for OAuth 2
            update_token = kwargs.pop('update_token', None)
            if update_token is None and self.update_token:
                update_token = functools.partial(self.update_token, name=name)
            if update_token:
                kwargs['update_token'] = update_token
        return kwargs

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

    def __init__(self, name, fetch_token=None, update_token=None,
                 fetch_request_token=None, save_request_token=None, **kwargs):
        self.name = name
        self._fetch_token = fetch_token
        self._fetch_request_token = fetch_request_token
        self._save_request_token = save_request_token

        super(RemoteApp, self).__init__(**kwargs)

        if kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = update_token

    @property
    def token(self):
        ctx = _app_ctx_stack.top
        token = getattr(ctx, 'authlib_client_oauth_token', None)
        if token:
            return token
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        ctx = _app_ctx_stack.top
        ctx.authlib_client_oauth_token = token

    def request(self, method, url, token=None, **kwargs):
        if token is None and not kwargs.get('withhold_token'):
            token = self.token
        return super(RemoteApp, self).request(
            method, url, token=token, **kwargs)

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        if redirect_uri:
            key = '_{}_callback_'.format(self.name)
            session[key] = redirect_uri

        if self.request_token_url:
            save_request_token = self._save_request_token
        else:
            save_request_token = None

        uri, state = self.generate_authorize_redirect(
            redirect_uri,
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
            request_token = self._fetch_request_token()
            params = request.args.to_dict(flat=True)
        else:
            request_token = None
            if request.method == 'GET':
                params = {'code': request.args['code']}
                request_state = request.args.get('state')
            else:
                params = {'code': request.form['code']}
                request_state = request.form.get('state')
            # verify state
            state_key = '_{}_state_'.format(self.name)
            state = session.pop(state_key, None)
            if state != request_state:
                raise OAuthException(
                    'State not equal in request and response.')
            if state:
                params['state'] = state

        cb_key = '_{}_callback_'.format(self.name)
        redirect_uri = session.pop(cb_key, None)
        params.update(kwargs)
        token = self.fetch_access_token(redirect_uri, request_token, **params)
        self.token = token
        return token
