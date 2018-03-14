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
    create_query_client_func,
    create_query_token_func,
    register_authorization_hooks,
    create_exists_nonce_func as create_db_exists_nonce_func,
)
from authlib.flask.oauth1.cache import (
    register_temporary_credential_hooks,
    register_nonce_hooks,
    create_exists_nonce_func as create_cache_exists_nonce_func,
)
from authlib.specs.rfc5849 import OAuth1Error
from authlib.common.urls import url_decode, url_encode
from authlib.common.encoding import to_unicode
from tests.util import read_file_path
from ..cache import SimpleCache
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id


class Client(db.Model, OAuth1ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    def get_rsa_public_key(self):
        return read_file_path('rsa_public.pem')


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
    query_client = create_query_client_func(db.session, Client)
    server = AuthorizationServer(app, query_client=query_client)
    if use_cache:
        cache = SimpleCache()
        register_nonce_hooks(server, cache)
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
        exists_nonce = create_cache_exists_nonce_func(cache)
    else:
        exists_nonce = create_db_exists_nonce_func(db.session, TimestampNonce)

    require_oauth = ResourceProtector(
        app,
        query_client=create_query_client_func(db.session, Client),
        query_token=create_query_token_func(db.session, TokenCredential),
        exists_nonce=exists_nonce,
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
