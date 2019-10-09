from flask import redirect, session
from flask import request as flask_req
from flask.signals import Namespace
from flask import _app_ctx_stack
from .._client import UserInfoMixin
from .._client import RemoteApp as _RemoteApp

__all__ = ['token_update', 'RemoteApp']

_signal = Namespace()
#: signal when token is updated
token_update = _signal.signal('token_update')


class RemoteApp(_RemoteApp, UserInfoMixin):
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, name, fetch_token=None, **kwargs):
        fetch_request_token = kwargs.pop('fetch_request_token', None)
        save_request_token = kwargs.pop('save_request_token', None)
        super(RemoteApp, self).__init__(name, fetch_token, **kwargs)

        self._fetch_request_token = fetch_request_token
        self._save_request_token = save_request_token

    def _send_token_update(self, token, refresh_token=None, access_token=None):
        self.token = token
        super(RemoteApp, self)._send_token_update(
            token, refresh_token, access_token
        )
        token_update.send(
            self,
            name=self.name,
            token=token,
            refresh_token=refresh_token,
            access_token=access_token,
        )

    def _generate_access_token_params(self, request):
        if self.request_token_url:
            return request.args.to_dict(flat=True)

        if request.method == 'GET':
            params = {
                'code': request.args['code'],
                'state': request.args.get('state'),
            }
        else:
            params = {
                'code': request.form['code'],
                'state': request.form.get('state'),
            }
        return params

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

    def save_authorize_state(self, redirect_uri=None, state=None, **kwargs):
        """Save ``redirect_uri``, ``state`` and other temporary data into
        session during authorize step.
        """
        # make it compatible with previous design
        flask_req.session = session
        self.save_authorize_data(
            flask_req,
            redirect_uri=redirect_uri,
            state=state,
            **kwargs
        )

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)

        if self.request_token_url:
            request_token = rv.pop('request_token', None)
            self._save_request_token(request_token)

        self.save_authorize_state(redirect_uri, **rv)
        return redirect(rv['url'])

    def authorize_access_token(self, **kwargs):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._fetch_request_token()
        else:
            request_token = None

        flask_req.session = session
        params = self.retrieve_access_token_params(flask_req, request_token)
        params.update(kwargs)
        token = self.fetch_access_token(**params)
        self.token = token
        return token

    def parse_id_token(self, token, claims_options=None):
        flask_req.session = session
        return self._parse_id_token(flask_req, token, claims_options)
