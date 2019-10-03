import time
import json
from sqlalchemy import Column, String, Boolean, Text, Integer
from sqlalchemy.ext.hybrid import hybrid_property
from authlib.oauth2.rfc6749 import (
    ClientMixin,
    TokenMixin,
    AuthorizationCodeMixin,
)
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.oidc.core import (
    AuthorizationCodeMixin as OIDCCodeMixin
)
from authlib.deprecate import deprecate

deprecate('Deprecate "authlib.flask.oauth2.sqla"', '1.0', 'Jeclj', 'sq')


class OAuth2ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120))
    issued_at = Column(
        Integer, nullable=False,
        default=lambda: int(time.time())
    )
    expires_at = Column(Integer, nullable=False, default=0)

    redirect_uri = Column(Text)
    token_endpoint_auth_method = Column(
        String(48), default='client_secret_basic')
    grant_type = Column(Text, nullable=False, default='')
    response_type = Column(Text, nullable=False, default='')
    scope = Column(Text, nullable=False, default='')

    client_name = Column(String(100))
    client_uri = Column(Text)
    logo_uri = Column(Text)
    contact = Column(Text)
    tos_uri = Column(Text)
    policy_uri = Column(Text)
    jwks_uri = Column(Text)
    jwks_text = Column(Text)
    i18n_metadata = Column(Text)

    software_id = Column(String(36))
    software_version = Column(String(48))

    def __repr__(self):
        return '<Client: {}>'.format(self.client_id)

    @hybrid_property
    def redirect_uris(self):
        if self.redirect_uri:
            return self.redirect_uri.splitlines()
        return []

    @redirect_uris.setter
    def redirect_uris(self, value):
        self.redirect_uri = '\n'.join(value)

    @hybrid_property
    def grant_types(self):
        if self.grant_type:
            return self.grant_type.splitlines()
        return []

    @grant_types.setter
    def grant_types(self, value):
        self.grant_type = '\n'.join(value)

    @hybrid_property
    def response_types(self):
        if self.response_type:
            return self.response_type.splitlines()
        return []

    @response_types.setter
    def response_types(self, value):
        self.response_type = '\n'.join(value)

    @hybrid_property
    def contacts(self):
        if self.contact:
            return json.loads(self.contact)
        return []

    @contacts.setter
    def contacts(self, value):
        self.contact = json.dumps(value)

    @hybrid_property
    def jwks(self):
        if self.jwks_text:
            return json.loads(self.jwks_text)
        return None

    @jwks.setter
    def jwks(self, value):
        self.jwks_text = json.dumps(value)

    @hybrid_property
    def client_metadata(self):
        """Implementation for Client Metadata in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 2`_.

        .. _`Section 2`: https://tools.ietf.org/html/rfc7591#section-2
        """
        keys = [
            'redirect_uris', 'token_endpoint_auth_method', 'grant_types',
            'response_types', 'client_name', 'client_uri', 'logo_uri',
            'scope', 'contacts', 'tos_uri', 'policy_uri', 'jwks_uri', 'jwks',
        ]
        metadata = {k: getattr(self, k) for k in keys}
        if self.i18n_metadata:
            metadata.update(json.loads(self.i18n_metadata))
        return metadata

    @client_metadata.setter
    def client_metadata(self, value):
        i18n_metadata = {}
        for k in value:
            if hasattr(self, k):
                setattr(self, k, value[k])
            elif '#' in k:
                i18n_metadata[k] = value[k]

        self.i18n_metadata = json.dumps(i18n_metadata)

    @property
    def client_info(self):
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`_.

        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        return dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_id_issued_at=self.issued_at,
            client_secret_expires_at=self.expires_at,
        )

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        if self.response_type:
            return response_type in self.response_types
        return False

    def check_grant_type(self, grant_type):
        if self.grant_type:
            return grant_type in self.grant_types
        return False


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    redirect_uri = Column(Text, default='')
    response_type = Column(Text, default='')
    scope = Column(Text, default='')
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

    def get_auth_time(self):
        return self.auth_time


class OIDCAuthorizationCodeMixin(OAuth2AuthorizationCodeMixin, OIDCCodeMixin):
    nonce = Column(Text)

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


def create_query_client_func(session, client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param client_model: Client model class
    """
    def query_client(client_id):
        q = session.query(client_model)
        return q.filter_by(client_id=client_id).first()
    return query_client


def create_save_token_func(session, token_model):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(
            client_id=client.client_id,
            user_id=user_id,
            **token
        )
        session.add(item)
        session.commit()
    return save_token


def create_query_token_func(session, token_model):
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    def query_token(token, token_type_hint, client):
        q = session.query(token_model)
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
    return query_token


def create_revocation_endpoint(session, token_model):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from authlib.oauth2.rfc7009 import RevocationEndpoint
    query_token = create_query_token_func(session, token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            return query_token(token, token_type_hint, client)

        def revoke_token(self, token):
            token.revoked = True
            session.add(token)
            session.commit()

    return _RevocationEndpoint


def create_bearer_token_validator(session, token_model):
    """Create an bearer token validator class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            q = session.query(token_model)
            return q.filter_by(access_token=token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
