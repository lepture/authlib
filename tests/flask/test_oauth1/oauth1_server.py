import os
import unittest
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from authlib.flask.oauth1 import (
    AuthorizationServer,
)
from authlib.flask.oauth1.sqla import (
    OAuth1ClientMixin,
    OAuth1AuthorizationCredentialMixin,
    register_authorization_hooks,
)
from authlib.specs.rfc5849 import OAuth1Error
from authlib.common.urls import url_decode
from authlib.common.encoding import to_unicode
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


class Token(db.Model, OAuth1AuthorizationCredentialMixin):
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

    @app.route('/oauth/initiate', methods=['POST'])
    def initiate():
        return server.create_temporary_credential_response()

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        if request.method == 'GET':
            try:
                server.validate_authorization_request()
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
        return server.create_authorization_response(grant_user)

    @app.route('/oauth/token', methods=['GET', 'POST'])
    def issue_token():
        return server.create_token_response()

    return server


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


def decode_response(data):
    return dict(url_decode(to_unicode(data)))
