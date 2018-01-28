from flask import json
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import AuthorizationCodeGrant, PasswordGrant
from .oauth2_server import create_authorization_server


class PasswordTest(TestCase):
    def prepare_data(self):
        server = create_authorization_server(self.app)
        server.register_grant_endpoint(AuthorizationCodeGrant)
        server.register_grant_endpoint(PasswordGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='password-client',
            client_secret='password-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile',
            is_confidential=True,
        )
        db.session.add(client)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'ok',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'password-client', 'invalid-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'ok',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

    def test_invalid_scope(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'password-client', 'password-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'ok',
            'scope': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_scope')

    def test_invalid_request(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'password-client', 'password-secret'
        )

        rv = self.client.get('/oauth/token', data={
            'grant_type': 'password',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_grant')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'wrong',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_grant')

    def test_authorize_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'password-client', 'password-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'ok',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
