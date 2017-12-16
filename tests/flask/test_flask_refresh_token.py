from flask import json
from .oauth2_server import db, User, Client, Token
from .oauth2_server import TestCase
from .oauth2_server import RefreshTokenGrant
from .oauth2_server import create_authorization_server


class RefreshTokenTest(TestCase):
    def prepare_data(self, is_confidential=True):
        server = create_authorization_server(self.app)
        server.register_grant_endpoint(RefreshTokenGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='refresh-client',
            client_secret='refresh-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile',
            is_confidential=is_confidential,
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self, scope='profile'):
        token = Token(
            user_id=1,
            client_id='refresh-client',
            token_type='bearer',
            access_token='a1',
            refresh_token='r1',
            scope=scope,
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'foo',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'invalid-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'foo',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'refresh-client', 'invalid-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'foo',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

    def test_public_client(self):
        self.prepare_data(False)
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'r1',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'unauthorized_client')

    def test_invalid_refresh_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'foo',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_invalid_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'r1',
            'scope': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_scope')

    def test_invalid_scope_none(self):
        self.prepare_data()
        self.create_token(scope=None)
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'r1',
            'scope': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_scope')

    def test_authorize_token_no_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'r1',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)

    def test_authorize_token_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'refresh-client', 'refresh-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'refresh_token',
            'refresh_token': 'r1',
            'scope': 'profile',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
