import functools
from django.conf import settings
from .remote_app import RemoteApp
from ..oauth_client import OAUTH_CLIENT_PARAMS

__all__ = ['OAuth']


class OAuth(object):
    """Registry for oauth clients.

    Create an instance for registry::

        oauth = OAuth()
    """

    def __init__(self, fetch_token=None):
        self._clients = {}
        self.fetch_token = fetch_token

    def register(self, name, overwrite=False, **kwargs):
        """Registers a new remote application.

        :param name: Name of the remote application.
        :param overwrite: Overwrite existing config with django settings.
        :param kwargs: Parameters for :class:`RemoteApp`.

        Find parameters from :class:`~authlib.client.OAuthClient`.
        When a remote app is registered, it can be accessed with
        *named* attribute::

            oauth.register('twitter', client_id='', ...)
            oauth.twitter.get('timeline')
        """
        client_cls = kwargs.pop('client_cls', RemoteApp)
        fetch_token = kwargs.pop('fetch_token', None)
        if not fetch_token and self.fetch_token:
            fetch_token = functools.partial(self.fetch_token, name)
        config = _get_conf(name)
        if config:
            kwargs = _config_client(config, kwargs, overwrite)

        compliance_fix = kwargs.pop('compliance_fix', None)
        client = client_cls(name, fetch_token=fetch_token, **kwargs)
        if compliance_fix:
            client.compliance_fix = compliance_fix

        self._clients[name] = client
        return client

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if key in self._clients:
                return self._clients[key]
            raise AttributeError('No such client: %s' % key)


def _get_conf(name):
    config = getattr(settings, 'AUTHLIB_OAUTH_CLIENTS', None)
    if config:
        return config.get(name)


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
