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
from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant,
    RefreshTokenGrant as _RefreshTokenGrant,
)
from authlib.specs.rfc7523 import JWTBearerGrant as _JWTBearerGrant
from authlib.specs.oidc.grants import (
    OpenIDCodeGrant as _OpenIDCodeGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.specs.oidc import UserInfo

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'
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


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)

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
    def create_authorization_code(self, client, grant_user, request):
        code = generate_token(48)
        nonce = request.data.get('nonce')
        item = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            nonce=nonce,
            user_id=grant_user.get_user_id(),
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

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    pass


class OpenIDCodeGrant(CodeGrantMixin, _OpenIDCodeGrant):
    pass


class OpenIDHybridGrant(CodeGrantMixin, _OpenIDHybridGrant):
    pass


class PasswordGrant(_PasswordGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and not item.is_refresh_token_expired():
            return item

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)


class JWTBearerGrant(_JWTBearerGrant):
    def authenticate_user(self, claims):
        return None

    def authenticate_client(self, claims):
        iss = claims['iss']
        return Client.query.filter_by(client_id=iss).first()

    def resolve_public_key(self, headers, payload):
        keys = {'1': 'foo', '2': 'bar'}
        return keys[headers['kid']]


def create_authorization_server(app):
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)

    def exists_nonce(nonce, req):
        exists = AuthorizationCode.query.filter_by(
            client_id=req.client_id, nonce=nonce
        ).first()
        return bool(exists)

    server = AuthorizationServer(
        app,
        query_client=query_client,
        save_token=save_token,
    )
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
                return error.error
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
