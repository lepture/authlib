from starlette.datastructures import URL
from starlette.responses import RedirectResponse

from ..base_client import BaseApp
from ..base_client import OAuthError
from ..base_client.async_app import AsyncOAuth1Mixin
from ..base_client.async_app import AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from ..httpx_client import AsyncOAuth1Client
from ..httpx_client import AsyncOAuth2Client
from ...jose import JsonWebToken, JsonWebKey
from ...oauth2.rfc9068.claims import JWTAccessTokenClaims


class StarletteAppMixin:
    async def save_authorize_data(self, request, **kwargs):
        state = kwargs.pop("state", None)
        if state:
            if self.framework.cache:
                session = None
            else:
                session = request.session
            await self.framework.set_state_data(session, state, kwargs)
        else:
            raise RuntimeError("Missing state value")

    async def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Starlette view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        # Handle Starlette >= 0.26.0 where redirect_uri may now be a URL and not a string
        if redirect_uri and isinstance(redirect_uri, URL):
            redirect_uri = str(redirect_uri)
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        await self.save_authorize_data(request, redirect_uri=redirect_uri, **rv)
        return RedirectResponse(rv["url"], status_code=302)


class StarletteOAuth1App(StarletteAppMixin, AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client

    async def authorize_access_token(self, request, **kwargs):
        params = dict(request.query_params)
        state = params.get("oauth_token")
        if not state:
            raise OAuthError(description='Missing "oauth_token" parameter')

        data = await self.framework.get_state_data(request.session, state)
        if not data:
            raise OAuthError(description='Missing "request_token" in temporary data')

        params["request_token"] = data["request_token"]
        params.update(kwargs)
        await self.framework.clear_state_data(request.session, state)
        return await self.fetch_access_token(**params)


class StarletteOAuth2App(
    StarletteAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp
):
    client_cls = AsyncOAuth2Client

    async def authorize_access_token(self, request, **kwargs):
        error = request.query_params.get("error")
        if error:
            description = request.query_params.get("error_description")
            raise OAuthError(error=error, description=description)

        params = {
            "code": request.query_params.get("code"),
            "state": request.query_params.get("state"),
        }

        if self.framework.cache:
            session = None
        else:
            session = request.session

        state_data = await self.framework.get_state_data(session, params.get("state"))
        await self.framework.clear_state_data(session, params.get("state"))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = await self.fetch_access_token(**params, **kwargs)

        if "id_token" in token and "nonce" in state_data:
            userinfo = await self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token

    async def decode_access_token(self, token, alg_values=None, **kwargs):
        claims_options = kwargs.pop("claims_options", None)
        if claims_options is None:
            metadata = await self.load_server_metadata()
            # RFC9068 Section 2.2 and 4
            claims_options = {
                "iss": {"essential": True, "value": metadata["issuer"]},
                "exp": {"essential": True},
                "aud": {"essential": True, "value": self.client_id},
                # As far as I know, there's no way to verify what the value of sub should be without being
                # responsible for requesting the access token to begin with
                "sub": {"essential": True},
                "client_id": {"essential": True},
                "iat": {"essential": True},
                "jti": {"essential": True},
            }

        # RFC9068: authorization servers and resource servers must support RS256
        if alg_values is None:
            alg_values = ["RS256"]
        jwt = JsonWebToken(alg_values)
        jwk_set = await self.fetch_jwk_set()

        claims_cls = kwargs.pop("claims_cls", JWTAccessTokenClaims)
        return jwt.decode(
            token,
            key=JsonWebKey.import_key_set(jwk_set),
            claims_cls=claims_cls,
            claims_options=claims_options,
            **kwargs
        )