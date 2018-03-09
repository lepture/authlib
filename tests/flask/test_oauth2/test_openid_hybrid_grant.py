from flask import json
from authlib.common.urls import urlparse, url_decode
from authlib.specs.rfc7519 import JWT
from authlib.specs.oidc import HybridIDToken
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import OpenIDHybridGrant
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
        server.register_grant(OpenIDHybridGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id='hybrid-client',
            client_secret='hybrid-secret',
            redirect_uris='https://a.b',
            scope='openid profile address',
            allowed_response_types='code id_token token',
            allowed_grant_types='authorization_code',
        )
        db.session.add(client)
        db.session.commit()

    def validate_claims(self, id_token, params):
        jwt = JWT()
        claims = jwt.decode(
            id_token, 'secret',
            claims_cls=HybridIDToken,
            claims_params=params
        )
        claims.validate()

    def test_code_access_token(self):
        # generate refresh token
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'client_id': 'hybrid-client',
            'response_type': 'code token',
            'state': 'bar',
            'nonce': 'abc',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b',
            'user_id': '1',
        })
        self.assertIn('code=', rv.location)
        self.assertIn('access_token=', rv.location)
        self.assertNotIn('id_token=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('hybrid-client', 'hybrid-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)

    def test_code_id_token(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'client_id': 'hybrid-client',
            'response_type': 'code id_token',
            'state': 'bar',
            'nonce': 'abc',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b',
            'user_id': '1',
        })
        self.assertIn('code=', rv.location)
        self.assertIn('id_token=', rv.location)
        self.assertNotIn('access_token=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.assertEqual(params['state'], 'bar')

        params['nonce'] = 'abc'
        params['client_id'] = 'hybrid-client'
        self.validate_claims(params['id_token'], params)

        code = params['code']
        headers = self.create_basic_header('hybrid-client', 'hybrid-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)

    def test_code_id_token_access_token(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'client_id': 'hybrid-client',
            'response_type': 'code id_token token',
            'state': 'bar',
            'nonce': 'abc',
            'scope': 'openid profile',
            'redirect_uri': 'https://a.b',
            'user_id': '1',
        })
        self.assertIn('code=', rv.location)
        self.assertIn('id_token=', rv.location)
        self.assertIn('access_token=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.assertEqual(params['state'], 'bar')
        self.validate_claims(params['id_token'], params)

        code = params['code']
        headers = self.create_basic_header('hybrid-client', 'hybrid-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)
