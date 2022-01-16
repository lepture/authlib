from quart import redirect, request, session
from quart import _app_ctx_stack
from ..base_client import OAuthError
from ..base_client import BaseApp
from ..base_client.async_app import AsyncOAuth1Mixin, AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from ..httpx_client import AsyncOAuth1Client, AsyncOAuth2Client


class QuartAppMixin(object):
    @property
    def token(self):
        ctx = _app_ctx_stack.top
        attr = '_oauth_token_{}'.format(self.name)
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
        attr = '_oauth_token_{}'.format(self.name)
        setattr(ctx, attr, token)

    def _get_requested_token(self, *args, **kwargs):
        return self.token

    async def save_authorize_data(self, **kwargs):
        state = kwargs.pop('state', None)
        if state:
            await self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError('Missing state value')

    async def authorize_redirect(self, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        await self.save_authorize_data(redirect_uri=redirect_uri, **rv)
        return redirect(rv['url'])


class QuartOAuth1App(QuartAppMixin, AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client

    async def authorize_access_token(self, **kwargs):
        params = request.args.to_dict(flat=True)
        state = params.get('oauth_token')
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = await self.framework.get_state_data(session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params['request_token'] = data['request_token']
        params.update(kwargs)
        await self.framework.clear_state_data(session, state)
        token = await self.fetch_access_token(**params)
        self.token = token
        return token


class QuartOAuth2App(QuartAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp):
    client_cls = AsyncOAuth2Client

    async def authorize_access_token(self, **kwargs):
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
            form = await request.form
            params = {
                'code': form['code'],
                'state': form.get('state'),
            }

        state_data = await self.framework.get_state_data(session, params.get('state'))
        params = self._format_state_params(state_data, params)
        token = await self.fetch_access_token(**params, **kwargs)
        self.token = token

        if 'id_token' in token and 'nonce' in state_data:
            userinfo = await self.parse_id_token(token, nonce=state_data['nonce'])
            token['userinfo'] = userinfo
        return token
