import os
import time
import base64
import unittest
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from authlib.common.security import generate_token
from authlib.common.encoding import to_bytes, to_unicode
from authlib.flask.oauth2.sqla import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from authlib.flask.oauth2 import (
    AuthorizationServer,
    ResourceProtector,
    current_token,
)
from authlib.specs.rfc6749 import OAuth2Error
from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    ImplicitGrant as _ImplicitGrant,
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant,
    ClientCredentialsGrant as _ClientCredentialsGrant,
    RefreshTokenGrant as _RefreshTokenGrant,
)

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def check_password(self, password):
        return password != 'wrong'


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')
    allowed_response_types = db.Column(db.Text, default='code token')

    def check_response_type(self, response_type):
        return response_type in self.allowed_response_types.split()


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')


class Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    def is_refresh_token_expired(self):
        expired_at = self.created_at + self.expires_in * 2
        return expired_at < time.time()

    @classmethod
    def query_token(cls, access_token):
        return cls.query.filter_by(access_token=access_token).first()


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, **kwargs):
        code = generate_token(48)
        item = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=kwargs.get('redirect_uri', ''),
            scope=kwargs.get('scope', ''),
            user_id=grant_user,
        )
        db.session.add(item)
        db.session.commit()
        return code

    def parse_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def create_access_token(self, token, client, authorization_code):
        item = Token(
            client_id=client.client_id,
            user_id=authorization_code.user_id,
            **token
        )
        db.session.add(item)
        db.session.commit()
        # we can add more data into token
        token['user_id'] = authorization_code.user_id


class ImplicitGrant(_ImplicitGrant):
    def create_access_token(self, token, client, grant_user):
        item = Token(
            client_id=client.client_id,
            user_id=grant_user,
            **token
        )
        db.session.add(item)
        db.session.commit()


class PasswordGrant(_PasswordGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user

    def create_access_token(self, token, client, user):
        item = Token(
            client_id=client.client_id,
            user_id=user.id,
            **token
        )
        db.session.add(item)
        db.session.commit()


class ClientCredentialsGrant(_ClientCredentialsGrant):
    def create_access_token(self, token, client):
        item = Token(
            client_id=client.client_id,
            user_id=client.user_id,
            **token
        )
        db.session.add(item)
        db.session.commit()


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and not item.is_refresh_token_expired():
            return item

    def create_access_token(self, token, client, authenticated_token):
        item = Token(
            client_id=client.client_id,
            user_id=authenticated_token.user_id,
            **token
        )
        db.session.add(item)
        db.session.delete(authenticated_token)
        db.session.commit()


def create_authorization_server(app):
    server = AuthorizationServer(Client, app)

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        if request.method == 'GET':
            try:
                server.validate_authorization_request()
                return 'ok'
            except OAuth2Error:
                return 'error'
        grant_user = request.form.get('user_id')
        if grant_user:
            user = User.query.get(int(grant_user))
            if user:
                grant_user = user.id
            else:
                grant_user = None
        return server.create_authorization_response(grant_user)

    @app.route('/oauth/token', methods=['GET', 'POST'])
    def issue_token():
        return server.create_token_response()

    @app.route('/oauth/revoke', methods=['POST'])
    def revoke_token():
        return server.create_revocation_response()

    return server


def create_resource_server(app):
    require_oauth = ResourceProtector(Token.query_token)

    @app.route('/user')
    @require_oauth('profile')
    def user_profile():
        user = current_token.user
        return jsonify(id=user.id, username=user.username)

    @app.route('/user/email')
    @require_oauth('email')
    def user_email():
        user = current_token.user
        return jsonify(email=user.username + '@example.com')

    @app.route('/info')
    @require_oauth()
    def public_info():
        return jsonify(status='ok')


def create_flask_app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = 'testing'
    app.config.update({
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite://'
    })
    return app


class TestCase(unittest.TestCase):
    def setUp(self):
        app = create_flask_app()

        self._ctx = app.app_context()
        self._ctx.push()

        db.init_app(app)
        db.create_all()

        self.app = app
        self.client = app.test_client()

    def tearDown(self):
        db.drop_all()
        self._ctx.pop()

    def create_basic_header(self, username, password):
        text = '{}:{}'.format(username, password)
        auth = to_unicode(base64.b64encode(to_bytes(text)))
        return {'Authorization': 'Basic ' + auth}
