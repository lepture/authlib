import time
import random
from sqlalchemy import Column, Boolean, String, Text, Integer
from authlib.specs.rfc6749.client_model import OAuth2Client
from authlib.common.security import generate_token


class OAuth2ClientMixin(OAuth2Client):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120), nullable=False)
    is_confidential = Column(Boolean, nullable=False, default=False)
    redirect_uris = Column(Text, nullable=False, default='')
    default_redirect_uri = Column(Text, nullable=False, default='')
    allowed_scopes = Column(Text, nullable=False, default='')

    @classmethod
    def get_by_client_id(cls, client_id):
        return cls.query.filter_by(client_id=client_id).first()

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris.split()

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


class OAuth2AuthorizationCodeMixin(object):
    code = Column(String(120), unique=True, nullable=False)
    client_id = Column(String(48))
    user_id = Column(String(255))
    redirect_uri = Column(Text, default='')
    scope = Column(Text, default='')

    # expires in 5 minutes by default
    expires_at = Column(
        Integer, nullable=False,
        default=lambda: int(time.time()) + 300
    )

    def get_authorization_code_user(self):
        """Get related user of this authorization code. Developers
        should implement it by themselves. An example would look like::

            def get_authorization_code_user(self):
                return User.query.get(self.user_id)

        :return: User model object
        """
        raise NotImplementedError()

    def save_authorization_code(self):
        """Save authorization code (itself) into database. Developers
        should implement it by themselves. An example would look like::

            def save_authorization_code(self):
                db.session.add(self)
                db.session.commit()
        """
        raise NotImplementedError()

    @classmethod
    def create_authorization_code(cls, client, user, **params):
        code = generate_token(random.randint(80, 120))
        authorization_code = cls(
            code=code,
            client_id=client.client_id,
            user_id=user.user_id,
            scope=params.get('scope', ''),
            redirect_uri=params.get('redirect_uri', '')
        )
        authorization_code.save_authorization_code()
        return authorization_code


class OAuth2TokenMixin(object):
    client_id = Column(String(48))
    user_id = Column(String(255))
    grant_type = Column(String(40))
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255))
    scope = Column(Text, default='')
    created_at = Column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    expires_at = Column(Integer, nullable=False, default=0)

    def save_token(self):
        """Save authorization code (itself) into database. Developers
        should implement it by themselves. An example would look like::

            def save_token(self):
                db.session.add(self)
                db.session.commit()
        """
        raise NotImplementedError()
