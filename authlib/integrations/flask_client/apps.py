from flask import g, redirect, request, session
from ..requests_client import OAuth1Session, OAuth2Session
from ..base_client import (
    BaseApp, OAuthError,
    OAuth1Mixin, OAuth2Mixin, OpenIDMixin,
)


class FlaskAppMixin(object):
    @property
    def token(self):
        attr = '_oauth_token_{}'.format(self.name)
        token = g.get(attr)
        if token:
            return token
        if self._fetch_token:
            token = self._fetch_token()
            self.token = token
            return token

    @token.setter
    def token(self, token):
        attr = '_oauth_token_{}'.format(self.name)
        setattr(g, attr, token)

    def _get_requested_token(self, *args, **kwargs):
        return self.token

    def save_authorize_data(self, **kwargs):
        state = kwargs.pop('state', None)
        if state:
            self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError('Missing state value')

    def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(redirect_uri=redirect_uri, **rv)
        return redirect(rv['url'])


class FlaskOAuth1App(FlaskAppMixin, OAuth1Mixin, BaseApp):
    client_cls = OAuth1Session

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        params = request.args.to_dict(flat=True)
        state = params.get('oauth_token')
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params['request_token'] = data['request_token']
        params.update(kwargs)
        self.framework.clear_state_data(session, state)
        token = self.fetch_access_token(**params)
        self.token = token
        return token


class FlaskOAuth2App(FlaskAppMixin, OAuth2Mixin, OpenIDMixin, BaseApp):
    client_cls = OAuth2Session

    def authorize_access_token(self, **kwargs):
        """Fetch access token in one step.

        :return: A token dict.
        """
        if request.method == 'GET':
            error = request.args.get('error')
            if error:
                description = request.args.get('error_description')
                raise OAuthError(error=error, description=description)

            params = {
                'code': request.args['code'],
                'state': request.args.get('state'),
            }
        else:
            params = {
                'code': request.form['code'],
                'state': request.form.get('state'),
            }

        claims_options = kwargs.pop('claims_options', None)
        state_data = self.framework.get_state_data(session, params.get('state'))
        self.framework.clear_state_data(session, params.get('state'))
        params = self._format_state_params(state_data, params)
        token = self.fetch_access_token(**params, **kwargs)
        self.token = token

        if 'id_token' in token and 'nonce' in state_data:
            userinfo = self.parse_id_token(token, nonce=state_data['nonce'], claims_options=claims_options)
            token['userinfo'] = userinfo
        return token
