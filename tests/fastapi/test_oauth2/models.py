import time
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin,
)
from authlib.oidc.core import UserInfo
from .database import Base, db


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password != 'wrong'

    def generate_user_info(self, scopes):
        profile = {'sub': str(self.id), 'name': self.username}
        return UserInfo(profile)


class Client(Base, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer, ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')


class AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)

    @property
    def user(self):
        return db.query(User).filter(
            User.id == self.user_id).first()


class Token(Base, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer, ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    def is_refresh_token_expired(self):
        expired_at = self.issued_at + self.expires_in * 2
        return expired_at < time.time()


class CodeGrantMixin(object):
    def query_authorization_code(self, code, client):
        item = db.query(AuthorizationCode).filter(
            AuthorizationCode.code == code,
            Client.client_id == client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.delete(authorization_code)
        db.commit()

    def authenticate_user(self, authorization_code):
        return db.query(User).filter(
            User.id == authorization_code.user_id).first()


def save_authorization_code(code, request):
    client = request.client
    auth_code = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        nonce=request.data.get('nonce'),
        user_id=request.user.id,
        code_challenge=request.data.get('code_challenge'),
        code_challenge_method=request.data.get('code_challenge_method'),
    )
    db.add(auth_code)
    db.commit()
    return auth_code


def exists_nonce(nonce, req):
    exists = db.query(AuthorizationCode).filter(
        Client.client_id == req.client_id, AuthorizationCode.nonce == nonce).first()
    return bool(exists)
