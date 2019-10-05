from starlette.responses import RedirectResponse
from authlib.integrations.requests_client import OAuthClient
from authlib.integrations._client import MismatchingStateError


__all__ = ["RemoteApp"]


_req_token_tpl = "_{}_authlib_req_token_"
_callback_tpl = "_{}_authlib_callback_"
_state_tpl = "_{}_authlib_state_"
_code_verifier_tpl = "_{}_authlib_code_verifier_"


class RemoteApp(OAuthClient):
    """Starlette integrated RemoteApp of :class:`~authlib.client.OAuthClient`.

    This has built-in hooks for ``OAuthClient``.

    """

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

        return self.fetch_access_token(
            redirect_uri, request_token, **{**params, **kwargs}
        )
