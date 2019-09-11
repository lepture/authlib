from flask import json
from authlib.oauth2.rfc7523 import JWTBearerGrant as _JWTBearerGrant
from .models import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class JWTBearerGrant(_JWTBearerGrant):
    def authenticate_user(self, client, claims):
        return None

    def authenticate_client(self, claims):
        iss = claims['iss']
        return Client.query.filter_by(client_id=iss).first()

    def resolve_public_key(self, headers, payload):
        keys = {'1': 'foo', '2': 'bar'}
        return keys[headers['kid']]


class JWTBearerGrantTest(TestCase):
    def prepare_data(self, grant_type=None):
        server = create_authorization_server(self.app)
        server.register_grant(JWTBearerGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        if grant_type is None:
            grant_type = JWTBearerGrant.GRANT_TYPE
        client = Client(
            user_id=user.id,
            client_id='jwt-client',
            client_secret='jwt-secret',
            redirect_uri='http://localhost/authorized',
            scope='profile',
            grant_type=grant_type,
        )
        db.session.add(client)
        db.session.commit()

    def test_missing_assertion(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': JWTBearerGrant.GRANT_TYPE
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')
        self.assertIn('assertion', resp['error_description'])

    def test_invalid_assertion(self):
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            'foo', issuer='jwt-client', audience='https://i.b/token',
            header={'alg': 'HS256', 'kid': '1'}
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': JWTBearerGrant.GRANT_TYPE,
            'assertion': assertion
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_grant')

    def test_authorize_token(self):
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            'foo', issuer='jwt-client', audience='https://i.b/token',
            subject='self', header={'alg': 'HS256', 'kid': '1'}
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': JWTBearerGrant.GRANT_TYPE,
            'assertion': assertion
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)

    def test_unauthorized_client(self):
        self.prepare_data('password')
        assertion = JWTBearerGrant.sign(
            'bar', issuer='jwt-client', audience='https://i.b/token',
            subject='self', header={'alg': 'HS256', 'kid': '2'}
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': JWTBearerGrant.GRANT_TYPE,
            'assertion': assertion
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'unauthorized_client')

    def test_token_generator(self):
        m = 'tests.flask.test_oauth2.oauth2_server:token_generator'
        self.app.config.update({'OAUTH2_ACCESS_TOKEN_GENERATOR': m})
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            'foo', issuer='jwt-client', audience='https://i.b/token',
            subject='self', header={'alg': 'HS256', 'kid': '1'}
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': JWTBearerGrant.GRANT_TYPE,
            'assertion': assertion
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('j-', resp['access_token'])
