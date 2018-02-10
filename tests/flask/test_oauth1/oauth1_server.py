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
    OAuth1TemporaryCredentialMixin,
    OAuth1TimestampNonceMixin,
    register_authorization_hooks,
)
from authlib.flask.oauth1.cache import (
    register_temporary_credential_hooks,
    register_exists_nonce,
)
from authlib.specs.rfc5849 import OAuth1Error
from authlib.common.urls import url_decode, url_encode
from authlib.common.encoding import to_unicode
from tests.util import get_rsa_public_key
from ..cache import SimpleCache
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id

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


class TokenCredential(db.Model, OAuth1TokenCredentialMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')


class TemporaryCredential(db.Model, OAuth1TemporaryCredentialMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')


class TimestampNonce(db.Model, OAuth1TimestampNonceMixin):
    id = db.Column(db.Integer, primary_key=True)


def create_authorization_server(app, use_cache=False):
    server = AuthorizationServer(app, client_model=Client)
    if use_cache:
        cache = SimpleCache()
        register_exists_nonce(server, cache)
        register_temporary_credential_hooks(server, cache)
        register_authorization_hooks(server, db.session, TokenCredential)
    else:
        register_authorization_hooks(
            server, db.session,
            token_credential_model=TokenCredential,
            temporary_credential_model=TemporaryCredential,
            timestamp_nonce_model=TimestampNonce,
        )

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
        user_id = request.form.get('user_id')
        if user_id:
            grant_user = User.query.get(int(user_id))
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
        cache = SimpleCache()
    else:
        cache = None

    def query_token(client_id, token_string):
        return TokenCredential.query.filter_by(
            client_id=client_id,
            oauth_token=token_string
        ).first()

    require_oauth = ResourceProtector(
        app, client_model=Client,
        cache=cache, query_token=query_token
    )

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
