import time
from sqlalchemy import Column, String, Boolean, Text, Integer
from authlib.oauth2.rfc6749 import (
    TokenMixin,
    AuthorizationCodeMixin,
)


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    redirect_uri = Column(Text, default='')
    response_type = Column(Text, default='')
    scope = Column(Text, default='')
    nonce = Column(Text)
    auth_time = Column(
        Integer, nullable=False,
        default=lambda: int(time.time())
    )

    code_challenge = Column(Text)
    code_challenge_method = Column(String(48))

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class OAuth2TokenMixin(TokenMixin):
    client_id = Column(String(48))
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255), index=True)
    scope = Column(Text, default='')
    revoked = Column(Boolean, default=False)
    issued_at = Column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    expires_in = Column(Integer, nullable=False, default=0)

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in
