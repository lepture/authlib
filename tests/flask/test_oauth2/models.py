import time
from flask_sqlalchemy import SQLAlchemy
from authlib.common.security import generate_token
from authlib.flask.oauth2.sqla import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OIDCAuthorizationCodeMixin,
)
from authlib.specs.oidc import UserInfo
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password != 'wrong'

    def generate_user_info(self, scopes):
        profile = {'sub': str(self.id), 'name': self.username}
        return UserInfo(profile)


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')


class AuthorizationCode(db.Model, OIDCAuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    code_challenge = db.Column(db.String(80))
    code_challenge_method = db.Column(db.String(10))

    @property
    def user(self):
        return User.query.get(self.user_id)


class Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expired_at = self.issued_at + self.expires_in * 2
        return expired_at < time.time()


class CodeGrantMixin(object):
    def parse_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


def generate_authorization_code(client, grant_user, request, **extra):
    code = generate_token(48)
    item = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        response_type=request.response_type,
        scope=request.scope,
        user_id=grant_user.get_user_id(),
        **extra
    )
    db.session.add(item)
    db.session.commit()
    return code


def exists_nonce(nonce, req):
    exists = AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)
