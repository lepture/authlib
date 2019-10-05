from django.dispatch import Signal
from django.http import HttpResponseRedirect
from authlib.integrations._client import MismatchingStateError
from authlib.integrations.requests_client import OAuthClient

__all__ = ['token_update', 'RemoteApp']

token_update = Signal(providing_args=['name', 'token'])
_req_token_tpl = '_{}_authlib_req_token_'
_callback_tpl = '_{}_authlib_callback_'
_state_tpl = '_{}_authlib_state_'
_code_verifier_tpl = '_{}_authlib_code_verifier_'


class RemoteApp(OAuthClient):
    """Django integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient.
    """
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
            def save_temporary_data(token):
                req_key = _req_token_tpl.format(self.name)
                request.session[req_key] = token
        else:
            def save_temporary_data(code_verifier):
                vf_key = _code_verifier_tpl.format(self.name)
                request.session[vf_key] = code_verifier

        uri, state = self.create_authorization_url(
            redirect_uri, save_temporary_data, **kwargs)

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
