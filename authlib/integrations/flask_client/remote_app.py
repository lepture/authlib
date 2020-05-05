from flask import redirect
from flask import request as flask_req
from flask import _app_ctx_stack
from ..base_client import RemoteApp


class FlaskRemoteApp(RemoteApp):
    """Flask integrated RemoteApp of :class:`~authlib.client.OAuthClient`.
    It has built-in hooks for OAuthClient. The only required configuration
    is token model.
    """

    def __init__(self, framework, name=None, fetch_token=None, **kwargs):
        fetch_request_token = kwargs.pop('fetch_request_token', None)
        save_request_token = kwargs.pop('save_request_token', None)
        super(FlaskRemoteApp, self).__init__(framework, name, fetch_token, **kwargs)

        self._fetch_request_token = fetch_request_token
        self._save_request_token = save_request_token

    def _on_update_token(self, token, refresh_token=None, access_token=None):
        self.token = token
        super(FlaskRemoteApp, self)._on_update_token(
            token, refresh_token, access_token
        )

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
        return super(FlaskRemoteApp, self).request(
            method, url, token=token, **kwargs)

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

        self.save_authorize_data(flask_req, redirect_uri=redirect_uri, **rv)
        return redirect(rv['url'])

    def authorize_access_token(self, **kwargs):
        """Authorize access token."""
        if self.request_token_url:
            request_token = self._fetch_request_token()
        else:
            request_token = None

        params = self.retrieve_access_token_params(flask_req, request_token)
        params.update(kwargs)
        token = self.fetch_access_token(**params)
        self.token = token
        return token

    def parse_id_token(self, token, claims_options=None, leeway=120):
        return self._parse_id_token(flask_req, token, claims_options, leeway)
