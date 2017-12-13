from flask import json
from authlib.common.urls import urlparse, url_decode
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import AuthorizationCodeGrant
from .oauth2_server import create_authorization_server


class AuthorizationCodeTest(TestCase):
    def prepare_data(self):
        server = create_authorization_server(self.app)
        server.register_endpoint_grant(AuthorizationCodeGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile address',
            is_confidential=True,
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=code-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_get_authorize(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'ok')

    def test_invalid_authorize(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url)
        self.assertIn('error=access_denied', rv.location)

        rv = self.client.post(self.authorize_url + '&scope=invalid')
        self.assertIn('error=invalid_scope', rv.location)

    def test_invalid_token(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
            'client_id': 'invalid-id',
            'client_secret': 'invalid-secret',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')
        self.assertIn('client_id', resp['error_description'])

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
            'client_id': 'code-client',
            'client_secret': 'invalid-secret',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
            'client_id': 'code-client',
            'client_secret': 'code-secret',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_authorize_token(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)
        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'code-client',
            'client_secret': 'code-secret',
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
