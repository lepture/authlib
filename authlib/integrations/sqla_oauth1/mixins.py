from sqlalchemy import Column, UniqueConstraint
from sqlalchemy import String, Integer, Text
from authlib.oauth1 import (
    ClientMixin,
    TemporaryCredentialMixin,
    TokenCredentialMixin,
)


class OAuth1ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120), nullable=False)
    default_redirect_uri = Column(Text, nullable=False, default='')

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

    def get_user_id(self):
        """A method to get the grant user information of this temporary
        credential. For instance, grant user is stored in database on
        ``user_id`` column::

            def get_user_id(self):
                return self.user_id

        :return: User ID
        """
        if hasattr(self, 'user_id'):
            return self.user_id
        else:
            raise NotImplementedError()

    def set_user_id(self, user_id):
        if hasattr(self, 'user_id'):
            setattr(self, 'user_id', user_id)
        else:
            raise NotImplementedError()

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


class OAuth1TimestampNonceMixin(object):
    __table_args__ = (
        UniqueConstraint(
            'client_id', 'timestamp', 'nonce', 'oauth_token',
            name='unique_nonce'
        ),
    )
    client_id = Column(String(48), nullable=False)
    timestamp = Column(Integer, nullable=False)
    nonce = Column(String(48), nullable=False)
    oauth_token = Column(String(84))


class OAuth1TokenCredentialMixin(TokenCredentialMixin):
    client_id = Column(String(48), index=True)
    oauth_token = Column(String(84), unique=True, index=True)
    oauth_token_secret = Column(String(84))

    def set_user_id(self, user_id):
        if hasattr(self, 'user_id'):
            setattr(self, 'user_id', user_id)
        else:
            raise NotImplementedError()

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret
