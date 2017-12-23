from flask import json
from .oauth2_server import db, User, Client, Token
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server
from .oauth2_server import create_resource_server


class AuthorizationTest(TestCase):
    def test_none_grant(self):
        create_authorization_server(self.app)
        authorize_url = (
            '/oauth/authorize?response_type=token'
            '&client_id=implicit-client'
        )
        rv = self.client.get(authorize_url)
        self.assertEqual(rv.data, b'error')

        rv = self.client.post(authorize_url, data={'user_id': '1'})
        self.assertNotEqual(rv.status, 200)

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'x',
        })
        data = json.loads(rv.data)
        self.assertEqual(data['error'], 'invalid_grant')


class ResourceTest(TestCase):
    def prepare_data(self):
        create_resource_server(self.app)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='resource-client',
            client_secret='resource-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile',
            is_confidential=True,
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self, expires_in=3600):
        token = Token(
            user_id=1,
            client_id='resource-client',
            token_type='bearer',
            access_token='a1',
            scope='profile',
            expires_in=expires_in,
        )
        db.session.add(token)
        db.session.commit()

    def create_bearer_header(self, token):
        return {'Authorization': 'Bearer ' + token}

    def test_invalid_token(self):
        self.prepare_data()

        rv = self.client.get('/user')
        self.assertEqual(rv.status_code, 401)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_token')

        headers = {'Authorization': 'invalid token'}
        rv = self.client.get('/user', headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_token')

        headers = self.create_bearer_header('invalid')
        rv = self.client.get('/user', headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_token')

    def test_expired_token(self):
        self.prepare_data()
        self.create_token(0)
        headers = self.create_bearer_header('a1')
        rv = self.client.get('/user', headers=headers)
        self.assertEqual(rv.status_code, 401)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_token')

    def test_insufficient_token(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_bearer_header('a1')
        rv = self.client.get('/user/email', headers=headers)
        self.assertEqual(rv.status_code, 403)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'insufficient_scope')

    def test_access_resource(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_bearer_header('a1')
        rv = self.client.get('/user', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['username'], 'foo')

        rv = self.client.get('/info', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['status'], 'ok')

