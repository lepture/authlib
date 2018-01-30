from sqlalchemy import Column, String, Text
from authlib.specs.rfc5849 import (
    ClientMixin,
    TemporaryCredentialMixin,
    TokenCredentialMixin,
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

    def get_client_secret(self):
        return self.client_secret

    def get_rsa_public_key(self):
        return None


class OAuth1TemporaryCredentialMixin(TemporaryCredentialMixin):
    client_id = Column(String(48), index=True)
    oauth_token = Column(String(84), unique=True, index=True)
    oauth_token_secret = Column(String(84))
    oauth_verifier = Column(String(84))
    oauth_callback = Column(Text, default='')

    def get_client_id(self):
        return self.client_id

    def get_redirect_uri(self):
        return self.oauth_callback

    def check_verifier(self, verifier):
        return self.oauth_verifier == verifier

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret


class OAuth1TokenCredentialMixin(TokenCredentialMixin):
    client_id = Column(String(48), index=True)
    oauth_token = Column(String(84), unique=True, index=True)
    oauth_token_secret = Column(String(84))

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret


def register_authorization_hooks(
        authorization_server, session,
        token_credential_model,
        temporary_credential_model=None):

    def create_token_credential(token, temporary_credential):
        item = token_credential_model(
            oauth_token=token['oauth_token'],
            oauth_token_secret=token['oauth_token_secret'],
            client_id=temporary_credential.get_client_id()
        )
        item.set_grant_user(temporary_credential.get_grant_user())
        session.add(item)
        session.commit()
        return item

    authorization_server.register_hook(
        'create_token_credential', create_token_credential
    )

    if temporary_credential_model is None:
        return
