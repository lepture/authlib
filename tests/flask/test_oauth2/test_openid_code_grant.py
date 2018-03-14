from flask import json
from authlib.common.urls import urlparse, url_decode, url_encode
from authlib.specs.rfc7519 import JWT
from authlib.specs.oidc import CodeIDToken
from tests.util import get_file_path
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import OpenIDCodeGrant
from .oauth2_server import create_authorization_server


class BaseTestCase(TestCase):
    def config_app(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY': 'secret',
            'OAUTH2_JWT_ALG': 'HS256',
        })

    def prepare_data(self):
        self.config_app()
        server = create_authorization_server(self.app)
        server.register_grant(OpenIDCodeGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
            redirect_uri='https://a.b',
            scope='openid profile address',
            response_type='code',
            grant_type='authorization_code',
        )
        db.session.add(client)
        db.session.commit()


class OpenIDCodeTest(BaseTestCase):
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

        jwt = JWT()
        claims = jwt.decode(
            resp['id_token'], 'secret',
            claims_cls=CodeIDToken,
            claims_options={'iss': {'value': 'Authlib'}}
        )
        claims.validate()

    def test_pure_code_flow(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'code',
            'client_id': 'code-client',
            'state': 'bar',
            'scope': 'profile',
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
        self.assertNotIn('id_token', resp)

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

    def test_prompt(self):
        self.prepare_data()
        params = [
            ('response_type', 'code'),
            ('client_id', 'code-client'),
            ('state', 'bar'),
            ('nonce', 'abc'),
            ('scope', 'openid profile'),
            ('redirect_uri', 'https://a.b')
        ]
        query = url_encode(params)
        rv = self.client.get('/oauth/authorize?' + query)
        self.assertEqual(rv.data, b'login')

        query = url_encode(params + [('user_id', '1')])
        rv = self.client.get('/oauth/authorize?' + query)
        self.assertEqual(rv.data, b'ok')

        query = url_encode(params + [('prompt', 'login')])
        rv = self.client.get('/oauth/authorize?' + query)
        self.assertEqual(rv.data, b'login')


class RSAOpenIDCodeTest(BaseTestCase):
    def config_app(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY_PATH': get_file_path('jwk_private.json'),
            'OAUTH2_JWT_ALG': 'RS256',
        })

    def get_validate_key(self):
        with open(get_file_path('jwk_public.json'), 'r') as f:
            return json.load(f)

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

        jwt = JWT()
        claims = jwt.decode(
            resp['id_token'], self.get_validate_key(),
            claims_cls=CodeIDToken,
            claims_options={'iss': {'value': 'Authlib'}}
        )
        claims.validate()


class JWKSOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY_PATH': get_file_path('jwks_private.json'),
            'OAUTH2_JWT_ALG': 'PS256',
        })

    def get_validate_key(self):
        with open(get_file_path('jwks_public.json'), 'r') as f:
            return json.load(f)


class ECOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY_PATH': get_file_path('ec_private.json'),
            'OAUTH2_JWT_ALG': 'ES256',
        })

    def get_validate_key(self):
        with open(get_file_path('ec_public.json'), 'r') as f:
            return json.load(f)


class PEMOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY_PATH': get_file_path('rsa_private.pem'),
            'OAUTH2_JWT_ALG': 'RS256',
        })

    def get_validate_key(self):
        with open(get_file_path('rsa_public.pem'), 'r') as f:
            return f.read()
