import time
from sqlalchemy import Column, Boolean, String, Text, Integer
from authlib.specs.rfc6749 import (
    ClientMixin, AuthorizationCodeMixin, TokenMixin
)


class OAuth2ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120), nullable=False)
    is_confidential = Column(Boolean, nullable=False, default=False)
    redirect_uris = Column(Text, nullable=False, default='')
    default_redirect_uri = Column(Text, nullable=False, default='')
    allowed_scopes = Column(Text, nullable=False, default='')

    @classmethod
    def get_by_client_id(cls, client_id):
        # TODO: remove in version 0.7
        return cls.query.filter_by(client_id=client_id).first()

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def check_redirect_uri(self, redirect_uri):
        if redirect_uri == self.default_redirect_uri:
            return True
        return redirect_uri in self.redirect_uris.split()

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_client_type(self, client_type):
        if client_type == 'confidential':
            return self.is_confidential
        if client_type == 'public':
            return not self.is_confidential
        raise ValueError('Invalid client_type')

    def check_response_type(self, response_type):
        return True

    def check_grant_type(self, grant_type):
        return True

    def check_requested_scopes(self, scopes):
        allowed = set(self.allowed_scopes.split())
        return allowed.issuperset(set(scopes))


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    redirect_uri = Column(Text, default='')
    scope = Column(Text, default='')
    # expires in 5 minutes by default
    expires_at = Column(
        Integer, nullable=False,
        default=lambda: int(time.time()) + 300
    )

    def is_expired(self):
        return self.expires_at < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class OAuth2TokenMixin(TokenMixin):
    client_id = Column(String(48))
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255), index=True)
    scope = Column(Text, default='')
    created_at = Column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    expires_in = Column(Integer, nullable=False, default=0)

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.created_at + self.expires_in


def create_query_client_func(session, model_class):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param model_class: Client class
    """
    def query_client(client_id):
        q = session.query(model_class)
        return q.filter_by(client_id=client_id).first()
    return query_client


def create_query_token_func(session, model_class):
    """Create an ``query_token`` function that can be used in
    resource protector.

    :param session: SQLAlchemy session
    :param model_class: Token class
    """
    def query_token(access_token):
        q = session.query(model_class)
        return q.filter_by(access_token=access_token).first()
    return query_token
