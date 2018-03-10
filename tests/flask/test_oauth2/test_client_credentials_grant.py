from flask import json
from authlib.specs.rfc6749.grants import ClientCredentialsGrant
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ClientCredentialsTest(TestCase):
    def prepare_data(self, grant_type='client_credentials'):
        server = create_authorization_server(self.app)
        server.register_grant(ClientCredentialsGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='credential-client',
            client_secret='credential-secret',
            redirect_uri='http://localhost/authorized',
            scope='profile',
            grant_type=grant_type,
        )
        db.session.add(client)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'credential-client', 'invalid-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

    def test_invalid_grant_type(self):
        self.prepare_data(grant_type='invalid')
        headers = self.create_basic_header(
            'credential-client', 'credential-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'unauthorized_client')

    def test_invalid_scope(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'credential-client', 'credential-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
            'scope': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_scope')

    def test_authorize_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'credential-client', 'credential-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'client_credentials',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
