from flask_sqlalchemy import SQLAlchemy

from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.oidc.core import UserInfo

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password != "wrong"

    def generate_user_info(self, scopes):
        profile = {"sub": str(self.id), "name": self.username}
        return UserInfo(profile)


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)

    @property
    def user(self):
        return db.session.get(User, self.user_id)


class Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def is_refresh_token_active(self):
        return not self.refresh_token_revoked_at


class CodeGrantMixin:
    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.get(User, authorization_code.user_id)


def save_authorization_code(code, request):
    client = request.client
    auth_code = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        nonce=request.data.get("nonce"),
        user_id=request.user.id,
        code_challenge=request.data.get("code_challenge"),
        code_challenge_method=request.data.get("code_challenge_method"),
    )
    db.session.add(auth_code)
    db.session.commit()
    return auth_code


def exists_nonce(nonce, req):
    exists = AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)
