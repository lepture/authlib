import os
import base64
import unittest
from flask import Flask, request, jsonify
from authlib.common.security import generate_token
from authlib.common.encoding import to_bytes, to_unicode
from authlib.common.urls import url_encode
from authlib.flask.oauth2.sqla import (
    create_bearer_token_validator,
    create_query_client_func,
    create_save_token_func,
)
from authlib.flask.oauth2 import (
    AuthorizationServer,
    ResourceProtector,
    current_token,
)
from authlib.specs.rfc6749 import OAuth2Error
from .models import db, User, Client, Token
from .models import exists_nonce

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'


def token_generator(client, grant_type, user=None, scope=None):
    token = '{}-{}'.format(client.client_id[0], grant_type)
    if user:
        token = '{}.{}'.format(token, user.get_user_id())
    return '{}.{}'.format(token, generate_token(32))


def create_authorization_server(app, lazy=False):
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)

    if lazy:
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    else:
        server = AuthorizationServer(app, query_client, save_token)
    server.register_hook('exists_nonce', exists_nonce)

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    def authorize():
        if request.method == 'GET':
            user_id = request.args.get('user_id')
            if user_id:
                end_user = User.query.get(int(user_id))
            else:
                end_user = None
            try:
                grant = server.validate_consent_request(end_user=end_user)
                return grant.prompt or 'ok'
            except OAuth2Error as error:
                return url_encode(error.get_body())
        user_id = request.form.get('user_id')
        if user_id:
            grant_user = User.query.get(int(user_id))
        else:
            grant_user = None
        return server.create_authorization_response(grant_user=grant_user)

    @app.route('/oauth/token', methods=['GET', 'POST'])
    def issue_token():
        return server.create_token_response()

    @app.route('/oauth/revoke', methods=['POST'])
    def revoke_token():
        return server.create_endpoint_response('revocation')

    @app.route('/oauth/introspect', methods=['POST'])
    def introspect_token():
        return server.create_endpoint_response('introspection')
    return server


def create_resource_server(app):
    require_oauth = ResourceProtector()
    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(BearerTokenValidator())

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

    @app.route('/acquire')
    def test_acquire():
        with require_oauth.acquire('profile') as token:
            user = token.user
            return jsonify(id=user.id, username=user.username)


def create_flask_app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = 'testing'
    app.config.update({
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        'OAUTH2_ERROR_URIS': [
            ('invalid_client', 'https://a.b/e#invalid_client')
        ]
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
