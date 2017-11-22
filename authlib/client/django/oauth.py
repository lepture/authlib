from django.conf import settings
from django.dispatch import Signal
from django.http import HttpResponseRedirect
from ..client import OAuthClient
from ..errors import OAuthException

__all__ = ['token_update', 'OAuth', 'RemoteApp']

token_update = Signal(providing_args=['name', 'token'])


class OAuth(object):
    """Registry for oauth clients.

    Create an instance for registry::

        oauth = OAuth()
    """

    def __init__(self):
        self._clients = {}

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
        client = RemoteApp(name, **kwargs)
        self._clients[name] = client
        return client

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            if key in self._clients:
                return self._clients[key]
            raise AttributeError('No such client: %s' % key)


class RemoteApp(OAuthClient):
    """Django integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient.
    """
    def __init__(self, name, token=None, *args, **kwargs):
        self.name = name
        self.token = token

        compliance_fix = kwargs.pop('compliance_fix', None)
        config = _get_conf(name)
        if config:
            keys = (
                'client_key', 'client_secret',
                'request_token_url', 'request_token_params',
                'access_token_url', 'access_token_params',
                'refresh_token_url', 'refresh_token_params',
                'authorize_url', 'api_base_url', 'client_kwargs',
            )
            for k in keys:
                if k not in kwargs:
                    kwargs[k] = config.get(k, None)

        super(RemoteApp, self).__init__(*args, **kwargs)

        self.compliance_fix = compliance_fix
        if self.client_kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = self._send_token_update

    def _send_token_update(self, token):
        token_update.send(
            sender=self.__class__,
            name=self.name,
            token=token,
        )

    def get_token(self):
        return self.token

    def authorize_redirect(self, request, callback_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Django view.
        :param callback_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        if callback_uri:
            key = '_{}_callback_'.format(self.name)
            request.session[key] = callback_uri

        if self.request_token_url:
            self.session.callback_uri = callback_uri
            params = {}
            if self.request_token_params:
                params.update(self.request_token_params)
            token = self.session.fetch_request_token(
                self.request_token_url, **params
            )
            # remember oauth_token, oauth_token_secret
            key = '_{}_req_token_'.format(self.name)
            request.session[key] = token
            url = self.session.authorization_url(
                self.authorize_url,  **kwargs)
            self.session.callback_uri = None
        else:
            self.session.redirect_uri = callback_uri
            url, state = self.session.authorization_url(
                self.authorize_url, **kwargs)
            if state:
                key = '_{}_state_'.format(self.name)
                request.session[key] = state
        return HttpResponseRedirect(url)

    def authorize_access_token(self, request):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        if self.request_token_url:
            key = '_{}_req_token_'.format(self.name)
            request_token = request.session.pop(key, None)
        else:
            request_token = None
            key = '_{}_state_'.format(self.name)
            state = request.session.pop(key, None)
            if state != request.GET.get('state'):
                raise OAuthException(
                    'State not equal in request and response.')

        key = '_{}_callback_'.format(self.name)
        callback_uri = request.session.get(key, None)
        params = request.GET.dict()
        return self.fetch_access_token(
            callback_uri,
            request_token,
            **params
        )


def _get_conf(name):
    config = getattr(settings, 'AUTHLIB_OAUTH_CLIENTS', None)
    if config:
        return config.get(name)
