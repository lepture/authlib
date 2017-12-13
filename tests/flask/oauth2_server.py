import unittest
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from authlib.common.security import generate_token
from authlib.server.flask.oauth2_sqla import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from authlib.server.flask.oauth2_server import (
    AuthorizationServer,
    ResourceServer,
)
from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)


class Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')


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

    @classmethod
    def query_token(cls, access_token):
        return cls.query.filter_by(access_token=access_token).first()

    @classmethod
    def query_revoke_token(cls, token, token_type_hint, client):
        if token_type_hint == 'access_token':
            item = cls.query.filter_by(access_token=token).first()
        elif token_type_hint == 'refresh_token':
            item = cls.query.filter_by(refresh_token=token).first()
        else:
            # without token_type_hint
            item = cls.query.filter_by(access_token=token).first()
            if not item:
                item = cls.query.filter_by(refresh_token=token).first()

        if item and item.client_id == client.client_id:
            return item


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, user, **kwargs):
        code = generate_token(48)
        item = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=kwargs.get('redirect_uri'),
            scope=kwargs.get('scope'),
            user_id=user.id,
        )
        db.session.add(item)
        db.session.commit()
        return code

    def parse_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if not item.is_expired():
            return item

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


def create_authorization_server(app):
    server = AuthorizationServer(Client, app)
    server.revoke_query_token = Token.query_revoke_token

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        if request.method == 'GET':
            server.validate_authorization_request()
            return 'ok'
        user_id = request.form.get('user_id')
        if user_id:
            user = User.query.get(int(user_id))
        else:
            user = None
        return server.create_authorization_response(user)

    @app.route('/oauth/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()

    return server


def create_resource_server():
    return ResourceServer(Token.query_token, lambda token: token.user)


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
