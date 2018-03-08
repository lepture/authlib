import time
from sqlalchemy import Column, String, Boolean, Text, Integer
from authlib.specs.rfc6749 import ClientMixin, TokenMixin
from authlib.specs.oidc import AuthorizationCodeMixin


class OAuth2ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120), nullable=False)
    redirect_uris = Column(Text, nullable=False, default='')
    default_redirect_uri = Column(Text, nullable=False, default='')
    scope = Column(Text, nullable=False, default='')

    def __repr__(self):
        return '<Client: {}>'.format(self.client_id)

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

    def check_token_endpoint_auth_method(self, method):
        if self.has_client_secret():
            return method == 'client_secret_basic'
        return method == 'none'

    def check_response_type(self, response_type):
        return True

    def check_grant_type(self, grant_type):
        return True

    def check_requested_scopes(self, scopes):
        allowed = set(self.scope.split())
        return allowed.issuperset(set(scopes))


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    redirect_uri = Column(Text, default='')
    scope = Column(Text, default='')
    nonce = Column(Text)
    auth_time = Column(
        Integer, nullable=False,
        default=lambda: int(time.time())
    )

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_nonce(self):
        return self.nonce

    def get_auth_time(self):
        return self.auth_time


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

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in


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


def create_save_token_func(session, model_class):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param model_class: Token class
    """
    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = model_class(
            client_id=client.client_id,
            user_id=user_id,
            **token
        )
        session.add(item)
        session.commit()
    return save_token


def create_revocation_endpoint(session, model_class):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param model_class: Token class
    """
    from authlib.specs.rfc7009 import RevocationEndpoint

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            q = session.query(model_class)
            q = q.filter_by(client_id=client.client_id, revoked=False)
            if token_type_hint == 'access_token':
                return q.filter_by(access_token=token).first()
            elif token_type_hint == 'refresh_token':
                return q.filter_by(refresh_token=token).first()
            # without token_type_hint
            item = q.filter_by(access_token=token).first()
            if item:
                return item
            return q.filter_by(refresh_token=token).first()

        def revoke_token(self, token):
            token.revoked = True
            session.add(token)
            session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(session, model_class):
    """Create an bearer token validator class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param model_class: Token class
    """
    from authlib.specs.rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            q = session.query(model_class)
            return q.filter_by(access_token=token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
