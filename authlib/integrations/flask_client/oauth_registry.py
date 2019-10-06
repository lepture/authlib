import uuid
from flask import session
from werkzeug.local import LocalProxy
from .._client import OAuth
from .remote_app import FlaskRemoteApp

__all__ = ['FlaskOAuth']
_req_token_tpl = '_{}_authlib_req_token_'


class FlaskOAuth(OAuth):
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
    remote_app_class = FlaskRemoteApp

    def __init__(self, app=None, cache=None, fetch_token=None, update_token=None):
        super(FlaskOAuth, self).__init__(fetch_token, update_token)

        self.app = app
        self.cache = cache
        if app:
            self.init_app(app)

    def init_app(self, app, cache=None, fetch_token=None, update_token=None):
        """Init app with Flask instance."""
        self.app = app
        if cache is not None:
            self.cache = cache

        if fetch_token:
            self.fetch_token = fetch_token
        if update_token:
            self.update_token = update_token

        app.extensions = getattr(app, 'extensions', {})
        app.extensions['authlib.integrations.flask_client'] = self

    def create_client(self, name):
        if not self.app:
            raise RuntimeError('OAuth is not init with Flask app.')
        return super(FlaskOAuth, self).create_client(name)

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
        if not self.oauth1_client_cls or not self.oauth2_client_cls:
            self.use_oauth_clients()

        self._registry[name] = (overwrite, kwargs)
        if self.app:
            return self.create_client(name)
        return LocalProxy(lambda: self.create_client(name))

    def load_config(self, name, params):
        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = self.app.config.get(conf_key, None)
            if v is not None:
                rv[k] = v
        return rv

    def generate_client_kwargs(self, name, overwrite, **kwargs):
        kwargs = super(FlaskOAuth, self).generate_client_kwargs(name, overwrite, **kwargs)

        if kwargs.get('request_token_url') and self.cache:
            _generate_oauth1_client_kwargs(self.cache, name, kwargs)
        return kwargs


def _generate_oauth1_client_kwargs(cache, name, kwargs):
    if not kwargs.get('fetch_request_token'):
        def fetch_request_token():
            key = _req_token_tpl.format(name)
            sid = session.pop(key, None)
            if not sid:
                return None

            token = cache.get(sid)
            cache.delete(sid)
            return token

        kwargs['fetch_request_token'] = fetch_request_token

    if not kwargs.get('save_request_token'):
        def save_request_token(token):
            key = _req_token_tpl.format(name)
            sid = uuid.uuid4().hex
            session[key] = sid
            cache.set(sid, token, timeout=600)

        kwargs['save_request_token'] = save_request_token
    return kwargs
