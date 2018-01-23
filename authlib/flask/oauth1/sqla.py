from sqlalchemy import Column, String, Text
from authlib.specs.rfc5849 import (
    ClientMixin, TemporaryCredentialMixin, TokenMixin
)


class OAuth1ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120), nullable=False)
    default_redirect_uri = Column(Text, nullable=False, default='')

    @classmethod
    def get_by_client_id(cls, client_id):
        return cls.query.filter_by(client_id=client_id).first()

    def get_default_redirect_uri(self):
        return self.default_redirect_uri


class OAuth1TemporaryCredentialMixin(TemporaryCredentialMixin):
    client_id = Column(String(48), index=True)
    oauth_token = Column(String(84), unique=True, index=True)
    oauth_token_secret = Column(String(84))
    oauth_verifier = Column(String(84))
    oauth_callback = Column(Text, default='')

    def get_redirect_uri(self):
        return self.oauth_callback

    def check_verifier(self, verifier):
        return self.oauth_verifier == verifier

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret


class OAuth1AccessTokenMixin(TokenMixin):
    client_id = Column(String(48), index=True)
    oauth_token = Column(String(84), unique=True, index=True)
    oauth_token_secret = Column(String(84))

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret
