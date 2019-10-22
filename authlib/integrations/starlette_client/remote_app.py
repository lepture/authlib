from starlette.responses import RedirectResponse
from ..asgi_client import AsyncBaseApp


__all__ = ['RemoteApp']


class RemoteApp(AsyncBaseApp):
    """A RemoteApp for Starlette framework."""

    def _generate_access_token_params(self, request):
        if self.request_token_url:
            return request.scope
        return {
            'code': request.query_params.get('code'),
            'state': request.query_params.get('state'),
        }

    async def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: Starlette Request instance.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: Starlette ``RedirectResponse`` instance.
        """
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv['url'])

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

        nonce = self._get_session_data(request, 'nonce')
        return await self._parse_id_token(token, nonce, claims_options)
