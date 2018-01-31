import os
import unittest
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from authlib.flask.oauth1 import (
    AuthorizationServer, ResourceProtector, current_credential
)
from authlib.flask.oauth1.sqla import (
    OAuth1ClientMixin,
    OAuth1TokenCredentialMixin,
    register_authorization_hooks,
)
from authlib.specs.rfc5849 import OAuth1Error
from authlib.common.urls import url_decode, url_encode
from authlib.common.encoding import to_unicode
from tests.util import get_rsa_public_key
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def check_password(self, password):
        return password != 'wrong'


class Client(db.Model, OAuth1ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    def get_rsa_public_key(self):
        return get_rsa_public_key()


class Token(db.Model, OAuth1TokenCredentialMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    def set_grant_user(self, grant_user):
        self.user_id = grant_user


def create_authorization_server(app, use_cache=False):
    if use_cache:
        app.config.update({'OAUTH1_AUTH_CACHE_TYPE': 'simple'})

    server = AuthorizationServer(Client, app=app)
    register_authorization_hooks(server, db.session, Token)

    @app.route('/oauth/initiate', methods=['GET', 'POST'])
    def initiate():
        return server.create_temporary_credential_response()

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        if request.method == 'GET':
            try:
                server.check_authorization_request()
                return 'ok'
            except OAuth1Error:
                return 'error'
        grant_user = request.form.get('user_id')
        if grant_user:
            user = User.query.get(int(grant_user))
            if user:
                grant_user = user.id
            else:
                grant_user = None
        try:
            return server.create_authorization_response(grant_user)
        except OAuth1Error as error:
            return url_encode(error.get_body())

    @app.route('/oauth/token', methods=['POST'])
    def issue_token():
        return server.create_token_response()

    return server


def create_resource_server(app, use_cache=False):
    if use_cache:
        app.config.update({'OAUTH1_RESOURCE_CACHE_TYPE': 'simple'})

    def get_token(client_id, token_string):
        return Token.query.filter_by(
            client_id=client_id,
            oauth_token=token_string
        ).first()

    require_oauth = ResourceProtector(Client, get_token, app=app)

    @app.route('/user')
    @require_oauth()
    def user_profile():
        user = current_credential.user
        return jsonify(id=user.id, username=user.username)


def create_flask_app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = 'testing'
    app.config.update({
        'OAUTH1_SUPPORTED_SIGNATURE_METHODS': ['PLAINTEXT', 'HMAC-SHA1', 'RSA-SHA1'],
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


def decode_response(data):
    return dict(url_decode(to_unicode(data)))
