import functools
from .remote_app import RemoteApp

__all__ = ["OAuth"]


class OAuth(object):
    """Registry for oauth clients.

    Create an instance for registry::

        oauth = OAuth()
    """

    def __init__(self, fetch_token=None):
        self._clients = {}
        self.fetch_token = fetch_token

    def register(self, name, **kwargs):
        """Register a new remote application.

        :param name: Name of the remote application.
        :param kwargs: Parameters for :class:`RemoteApp`.

        Find parameters from :class:`~authlib.client.OAuthClient`.
        When a remote app is registered, it can be accessed with
        *named* attribute::

            oauth.register('twitter', client_id='', ...)
            oauth.twitter.get('timeline')

        """
        client_cls = kwargs.pop("client_cls", RemoteApp)
        fetch_token = kwargs.pop("fetch_token", None)
        if not fetch_token and self.fetch_token:
            fetch_token = functools.partial(self.fetch_token, name)

        compliance_fix = kwargs.pop("compliance_fix", None)
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
            raise AttributeError("No such client: %s" % key)
