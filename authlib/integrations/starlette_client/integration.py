from starlette.responses import RedirectResponse
from ..httpx_client import AsyncOAuth1Client, AsyncOAuth2Client
from ..base_client import FrameworkIntegration
from ..base_client.async_app import AsyncRemoteApp


class StartletteIntegration(FrameworkIntegration):
    oauth1_client_cls = AsyncOAuth1Client
    oauth2_client_cls = AsyncOAuth2Client

    def update_token(self, token, refresh_token=None, access_token=None):
        pass

    def generate_access_token_params(self, request_token_url, request):
        if request_token_url:
            return dict(request.query_params)
        return {
            'code': request.query_params.get('code'),
            'state': request.query_params.get('state'),
        }

    @staticmethod
    def load_config(oauth, name, params):
        if not oauth.config:
            return {}

        rv = {}
        for k in params:
            conf_key = '{}_{}'.format(name, k).upper()
            v = oauth.config.get(conf_key, default=None)
            if v is not None:
                rv[k] = v
        return rv


class StarletteRemoteApp(AsyncRemoteApp):

    async def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.
        """
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv['url'], status_code=302)

    async def authorize_access_token(self, request, **kwargs):
        """Fetch an access token.

        :param request: Starlette Request instance.
        :return: A token dict.
        """
        params = self.retrieve_access_token_params(request)
        params.update(kwargs)
        return await self.fetch_access_token(**params)

    async def parse_id_token(self, request, token, claims_options=None):
        """Return an instance of UserInfo from token's ``id_token``."""
        if 'id_token' not in token:
            return None

        nonce = self.framework.get_session_data(request, 'nonce')
        return await self._parse_id_token(token, nonce, claims_options)
