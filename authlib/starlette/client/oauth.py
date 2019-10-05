import functools
from starlette.responses import RedirectResponse
from authlib.client import OAuthClient
from authlib.client.errors import MismatchingStateError


__all__ = ["OAuth", "RemoteApp"]


_req_token_tpl = "_{}_authlib_req_token_"
_callback_tpl = "_{}_authlib_callback_"
_state_tpl = "_{}_authlib_state_"
_code_verifier_tpl = "_{}_authlib_code_verifier_"


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


class RemoteApp(OAuthClient):
    """Starlette integrated RemoteApp of :class:`~authlib.client.OAuthClient`.

    This has built-in hooks for ``OAuthClient``.

    """

    def __init__(self, name, fetch_token=None, **kwargs):
        super(RemoteApp, self).__init__(**kwargs)

        self.name = name
        self._fetch_token = fetch_token

    def save_authorize_state(self, request, redirect_uri=None, state=None):
        """Save ``redirect_uri`` and ``state`` into session during authorization step.

        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param state: State string preventing CSRF.

        """
        if redirect_uri:
            key = _callback_tpl.format(self.name)
            request.session[key] = redirect_uri

        if state:
            state_key = _state_tpl.format(self.name)
            request.session[state_key] = state

    def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.

        """
        if self.request_token_url:

            def save_temporary_data(token):
                req_key = _req_token_tpl.format(self.name)
                request.session[req_key] = token

        else:

            def save_temporary_data(code_verifier):
                vf_key = _code_verifier_tpl.format(self.name)
                request.session[vf_key] = code_verifier

        uri, state = self.create_authorization_url(
            redirect_uri, save_temporary_data, **kwargs
        )
        self.save_authorize_state(request, redirect_uri, state)
        return RedirectResponse(uri)

    def _send_token_update(self, token):
        pass

    def authorize_access_token(self, request, **kwargs):
        """Fetch an access token.

        :param request: Starlette Request instance.
        :return: A token dict.

        """
        if self.request_token_url:
            req_key = _req_token_tpl.format(self.name)
            request_token = request.session.pop(req_key, None)
            params = request.scope
        else:
            request_token = None

            params = {}
            params["code"] = request.query_params["code"]

            request_state = request.query_params["state"]
            state_key = _state_tpl.format(self.name)
            session_state = request.session.pop(state_key, None)

            if session_state:
                if session_state != request_state:
                    raise MismatchingStateError()
                params["state"] = session_state

            vf_key = _code_verifier_tpl.format(self.name)
            code_verifier = request.session.pop(vf_key, None)
            if code_verifier:
                params["code_verifier"] = code_verifier

        cb_key = _callback_tpl.format(self.name)
        redirect_uri = request.session.get(cb_key, None)

        return self.fetch_access_token(redirect_uri, request_token, **{**params, **kwargs})
