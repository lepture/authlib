import uuid
from flask import session
from werkzeug.local import LocalProxy
from .integration import FlaskIntegration
from .remote_app import FlaskRemoteApp
from ..base_client import BaseOAuth

__all__ = ['OAuth']
_req_token_tpl = '_{}_authlib_req_token_'


class OAuth(BaseOAuth):
    """A Flask OAuth registry for oauth clients.

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
    framework_client_cls = FlaskRemoteApp
    framework_integration_cls = FlaskIntegration

    def __init__(self, app=None, cache=None, fetch_token=None, update_token=None):
        super(OAuth, self).__init__(fetch_token, update_token)

        self.app = app
        self.cache = cache
        if app:
            self.init_app(app)

    def init_app(self, app, cache=None, fetch_token=None, update_token=None):
        """Initialize lazy for Flask app. This is usually used for Flask application
        factory pattern.
        """
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
        return super(OAuth, self).create_client(name)

    def register(self, name, overwrite=False, **kwargs):
        self._registry[name] = (overwrite, kwargs)
        if self.app:
            return self.create_client(name)
        return LocalProxy(lambda: self.create_client(name))

    def generate_client_kwargs(self, name, overwrite, **kwargs):
        kwargs = super(OAuth, self).generate_client_kwargs(name, overwrite, **kwargs)

        if kwargs.get('request_token_url'):
            if self.cache:
                _add_cache_request_token(self.cache, name, kwargs)
            else:
                _add_session_request_token(name, kwargs)
        return kwargs


def _add_cache_request_token(cache, name, kwargs):
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
            cache.set(sid, token, 600)

        kwargs['save_request_token'] = save_request_token
    return kwargs


def _add_session_request_token(name, kwargs):
    if not kwargs.get('fetch_request_token'):
        def fetch_request_token():
            key = _req_token_tpl.format(name)
            return session.pop(key, None)

        kwargs['fetch_request_token'] = fetch_request_token

    if not kwargs.get('save_request_token'):
        def save_request_token(token):
            key = _req_token_tpl.format(name)
            session[key] = token

        kwargs['save_request_token'] = save_request_token

    return kwargs
