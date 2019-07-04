from authlib.oauth2.client_auth import TokenAuth
from authlib.oauth2.rfc7521 import AssertionClient as _AssertionClient
from authlib.oauth2.rfc7523 import JWTBearerGrant


class AssertionTokenAuth(TokenAuth):
    def ensure_refresh_token(self):
        if not self.token or self.token.is_expired() and self.client:
            return self.client.refresh_token()


class AssertionClient(_AssertionClient):
    token_auth_class = AssertionTokenAuth
    JWT_BEARER_GRANT_TYPE = JWTBearerGrant.GRANT_TYPE
    ASSERTION_METHODS = {
        JWT_BEARER_GRANT_TYPE: JWTBearerGrant.sign,
    }
    DEFAULT_GRANT_TYPE = JWT_BEARER_GRANT_TYPE
