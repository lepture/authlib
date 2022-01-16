# flake8: noqa
from werkzeug.local import LocalProxy
from ..base_client import BaseOAuth, OAuthError
from .integration import QuartIntegration, token_update
from .apps import QuartOAuth1App, QuartOAuth2App


class OAuth(BaseOAuth):
    oauth1_client_cls = QuartOAuth1App
    oauth2_client_cls = QuartOAuth2App
    framework_integration_cls = QuartIntegration

    def __init__(self, app=None, cache=None, fetch_token=None, update_token=None):
        super(OAuth, self).__init__(
            cache=cache, fetch_token=fetch_token, update_token=update_token)
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app, cache=None, fetch_token=None, update_token=None):
        """Initialize lazy for Quart app. This is usually used for Quart application
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
        app.extensions['authlib.integrations.quart_client'] = self

    def create_client(self, name):
        if not self.app:
            raise RuntimeError('OAuth is not init with Quart app.')
        return super(OAuth, self).create_client(name)

    def register(self, name, overwrite=False, **kwargs):
        self._registry[name] = (overwrite, kwargs)
        if self.app:
            return self.create_client(name)
        return LocalProxy(lambda: self.create_client(name))


__all__ = [
    'OAuth', 'QuartIntegration',
    'QuartOAuth1App', 'QuartOAuth2App',
    'token_update', 'OAuthError',
]
