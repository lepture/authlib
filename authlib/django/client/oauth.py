import functools
from django.conf import settings
from django.dispatch import Signal
from django.http import HttpResponseRedirect
from authlib.client.client import OAuthClient, OAUTH_CLIENT_PARAMS
from authlib.client.errors import MismatchingStateError

__all__ = ['token_update', 'OAuth', 'RemoteApp']

token_update = Signal(providing_args=['name', 'token'])
_req_token_tpl = '_{}_authlib_req_token_'
_callback_tpl = '_{}_authlib_callback_'
_state_tpl = '_{}_authlib_state_'
_code_verifier_tpl = '_{}_authlib_code_verifier_'


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


class RemoteApp(OAuthClient):
    """Django integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient.
    """
    def __init__(self, name, fetch_token=None, **kwargs):
        super(RemoteApp, self).__init__(**kwargs)

        self.name = name
        self._fetch_token = fetch_token
        if self.client_kwargs.get('refresh_token_url'):
            self.client_kwargs['token_updater'] = self._send_token_update

    def _send_token_update(self, token):
        token_update.send(
            sender=self.__class__,
            name=self.name,
            token=token,
        )

    def save_authorize_state(self, request, redirect_uri=None, state=None):
        """Save ``redirect_uri`` and ``state`` into session during
        authorize step."""
        if redirect_uri:
            key = _callback_tpl.format(self.name)
            request.session[key] = redirect_uri

        if state:
            state_key = _state_tpl.format(self.name)
            request.session[state_key] = state

    def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Django view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        if self.request_token_url:
            def save_request_token(token):
                req_key = _req_token_tpl.format(self.name)
                request.session[req_key] = token
        else:
            save_request_token = None

        def _save_code_verifier(code):
            vf_key = _code_verifier_tpl.format(self.name)
            request.session[vf_key] = code

        kwargs = self.add_code_challenge(_save_code_verifier, kwargs)
        uri, state = self.generate_authorize_redirect(
            redirect_uri,
            save_request_token,
            **kwargs
        )
        self.save_authorize_state(request, redirect_uri, state)
        return HttpResponseRedirect(uri)

    def authorize_access_token(self, request, **kwargs):
        """Fetch access token in one step.

        :param request: HTTP request instance from Django view.
        :return: A token dict.
        """
        if self.request_token_url:
            req_key = _req_token_tpl.format(self.name)
            request_token = request.session.pop(req_key, None)
            params = request.GET.dict()
        else:
            request_token = None
            params = _generate_oauth2_access_token_params(self.name, request)

        cb_key = _callback_tpl.format(self.name)
        redirect_uri = request.session.get(cb_key, None)
        params.update(kwargs)
        return self.fetch_access_token(
            redirect_uri,
            request_token,
            **params
        )


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


def _generate_oauth2_access_token_params(name, request):
    if request.method == 'GET':
        params = {'code': request.GET.get('code')}
        request_state = request.GET.get('state')
    else:
        params = {'code': request.POST.get('code')}
        request_state = request.POST.get('state')

    state_key = _state_tpl.format(name)
    state = request.session.pop(state_key, None)
    if state:
        if state != request_state:
            raise MismatchingStateError()
        params['state'] = state

    vf_key = _code_verifier_tpl.format(name)
    code_verifier = request.session.pop(vf_key, None)
    if code_verifier:
        params['code_verifier'] = code_verifier
    return params
