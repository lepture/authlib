from flask.signals import Namespace
from flask import request, redirect, session
from flask import _app_ctx_stack
from authlib.integrations._client import MismatchingStateError
from authlib.integrations.requests_client import OAuthClient

__all__ = ['token_update', 'RemoteApp']

_signal = Namespace()
#: signal when token is updated
token_update = _signal.signal('token_update')

_callback_tpl = '_{}_authlib_callback_'
_state_tpl = '_{}_authlib_state_'
_code_verifier_tpl = '_{}_authlib_code_verifier_'


class RemoteApp(OAuthClient):
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, name, fetch_token=None, **kwargs):
        update_token = kwargs.pop('update_token', None)
        fetch_request_token = kwargs.pop('fetch_request_token', None)
        save_request_token = kwargs.pop('save_request_token', None)

        super(RemoteApp, self).__init__(name, fetch_token, **kwargs)

        self._fetch_request_token = fetch_request_token
        self._save_request_token = save_request_token
        self._update_token = update_token

    def _send_token_update(self, token):
        self.token = token
        token_update.send(self, name=self.name, token=token)
        if callable(self._update_token):
            # TODO: deprecate
            self._update_token(token)

    @property
    def token(self):
        ctx = _app_ctx_stack.top
        attr = 'authlib_oauth_token_{}'.format(self.name)
        token = getattr(ctx, attr, None)
        if token:
            return token
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        ctx = _app_ctx_stack.top
        attr = 'authlib_oauth_token_{}'.format(self.name)
        setattr(ctx, attr, token)

    def request(self, method, url, token=None, **kwargs):
        if token is None and not kwargs.get('withhold_token'):
            token = self.token
        return super(RemoteApp, self).request(
            method, url, token=token, **kwargs)

    def save_authorize_state(self, redirect_uri=None, state=None):
        """Save ``redirect_uri`` and ``state`` into session during
        authorize step."""
        if redirect_uri:
            key = _callback_tpl.format(self.name)
            session[key] = redirect_uri

        if state:
            state_key = _state_tpl.format(self.name)
            session[state_key] = state

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        if self.request_token_url:
            save_temporary_data = self._save_request_token
        else:
            def save_temporary_data(code_verifier):
                vf_key = _code_verifier_tpl.format(self.name)
                session[vf_key] = code_verifier

        uri, state = self.create_authorization_url(
            redirect_uri, save_temporary_data, **kwargs)

        self.save_authorize_state(redirect_uri, state)
        return redirect(uri)

    def authorize_access_token(self, **kwargs):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._fetch_request_token()
            params = request.args.to_dict(flat=True)
        else:
            request_token = None
            params = _generate_oauth2_access_token_params(self.name)

        cb_key = _callback_tpl.format(self.name)
        redirect_uri = session.pop(cb_key, None)
        params.update(kwargs)
        token = self.fetch_access_token(redirect_uri, request_token, **params)
        self.token = token
        return token


def _generate_oauth2_access_token_params(name):
    if request.method == 'GET':
        params = {'code': request.args['code']}
        request_state = request.args.get('state')
    else:
        params = {'code': request.form['code']}
        request_state = request.form.get('state')

    state_key = _state_tpl.format(name)
    state = session.pop(state_key, None)
    if state:
        # verify state
        if state != request_state:
            raise MismatchingStateError()

        params['state'] = state

    vf_key = _code_verifier_tpl.format(name)
    code_verifier = session.pop(vf_key, None)
    if code_verifier:
        params['code_verifier'] = code_verifier
    return params
