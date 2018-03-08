from flask import json
from authlib.common.urls import urlparse, url_decode
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import OpenIDCodeGrant
from .oauth2_server import create_authorization_server


class OpenIDCodeTest(TestCase):
    def prepare_data(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY': 'secret',
            'OAUTH2_JWT_ALG': 'HS256',
        })
        server = create_authorization_server(self.app)
        server.register_grant(OpenIDCodeGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
            redirect_uris='https://a.b',
            scope='openid profile address',
            allowed_response_types='code',
            allowed_grant_types='authorization_code',
        )
        db.session.add(client)
        db.session.commit()

    def test_missing_redirect_uri(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'code',
            'client_id': 'code-client',
            'state': 'bar',
            'scope': 'openid profile',
            'user_id': '1'
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_authorize_token(self):
        # generate refresh token
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'code',
            'client_id': 'code-client',
            'state': 'bar',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b',
            'user_id': '1'
        })
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)

    def test_nonce_replay(self):
        self.prepare_data()
        data = {
            'response_type': 'code',
            'client_id': 'code-client',
            'user_id': '1',
            'state': 'bar',
            'nonce': 'abc',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b'
        }
        rv = self.client.post('/oauth/authorize', data=data)
        self.assertIn('code=', rv.location)

        rv = self.client.post('/oauth/authorize', data=data)
        self.assertIn('error=', rv.location)
