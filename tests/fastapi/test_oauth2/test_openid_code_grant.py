import json
from authlib.common.encoding import to_unicode
from authlib.common.urls import urlparse, url_decode, url_encode
from authlib.jose import JsonWebToken, JsonWebKey
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import get_file_path
from .database import db
from .models import User, Client, exists_nonce
from .models import CodeGrantMixin, save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server

DUMMY_JWT_CONFIG = {
    'key': 'secret',
    'alg': 'HS256',
    'iss': 'Authlib',
    'exp': 3600,
}


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class OpenIDCode(_OpenIDCode):
    def get_jwt_config(self, grant):
        return DUMMY_JWT_CONFIG

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class BaseTestCase(TestCase):
    def config_app(self):
        DUMMY_JWT_CONFIG.update({
            'iss': 'Authlib',
            'key': 'secret',
            'alg': 'HS256',
        })

    def prepare_data(self):
        self.config_app()
        server = create_authorization_server(self.app)
        server.register_grant(AuthorizationCodeGrant, [OpenIDCode()])

        user = User(username='foo')
        db.add(user)
        db.commit()

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
        )
        client.set_client_metadata({
            'redirect_uris': ['https://a.b'],
            'scope': 'openid profile address',
            'response_types': ['code'],
            'grant_types': ['authorization_code'],
        })
        db.add(client)
        db.commit()


class OpenIDCodeTest(BaseTestCase):
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
        self.assertIn('code=', rv.headers['location'])

        params = dict(url_decode(urlparse.urlparse(rv.headers['location']).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = rv.json()
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)

        jwt = JsonWebToken()
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
        self.assertIn('code=', rv.headers['location'])

        params = dict(url_decode(urlparse.urlparse(rv.headers['location']).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = rv.json()
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
        self.assertIn('code=', rv.headers['location'])

        rv = self.client.post('/oauth/authorize', data=data)
        self.assertIn('error=', rv.headers['location'])

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
        self.assertEqual(rv.json(), 'login')

        query = url_encode(params + [('user_id', '1')])
        rv = self.client.get('/oauth/authorize?' + query)
        self.assertEqual(rv.json(), 'ok')

        query = url_encode(params + [('prompt', 'login')])
        rv = self.client.get('/oauth/authorize?' + query)
        self.assertEqual(rv.json(), 'login')


class RSAOpenIDCodeTest(BaseTestCase):
    def config_app(self):
        jwt_key_path = get_file_path('jwk_private.json')
        with open(jwt_key_path, 'r') as f:
            jwt_key = json.load(f)

        DUMMY_JWT_CONFIG.update({
            'iss': 'Authlib',
            'key': jwt_key,
            'alg': 'RS256',
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
        self.assertIn('code=', rv.headers['location'])

        params = dict(url_decode(urlparse.urlparse(rv.headers['location']).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://a.b',
            'code': code,
        }, headers=headers)
        resp = rv.json()
        self.assertIn('access_token', resp)
        self.assertIn('id_token', resp)

        jwt = JsonWebToken()
        claims = jwt.decode(
            resp['id_token'],
            self.get_validate_key(),
            claims_cls=CodeIDToken,
            claims_options={'iss': {'value': 'Authlib'}}
        )
        claims.validate()


class JWKSOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        jwt_key_path = get_file_path('jwks_private.json')
        with open(jwt_key_path, 'r') as f:
            jwt_key = json.load(f)

        DUMMY_JWT_CONFIG.update({
            'iss': 'Authlib',
            'key': jwt_key,
            'alg': 'PS256',
        })

    def get_validate_key(self):
        with open(get_file_path('jwks_public.json'), 'r') as f:
            return JsonWebKey.import_key_set(json.load(f))


class ECOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        jwt_key_path = get_file_path('secp521r1-private.json')
        with open(jwt_key_path, 'r') as f:
            jwt_key = json.load(f)

        DUMMY_JWT_CONFIG.update({
            'iss': 'Authlib',
            'key': jwt_key,
            'alg': 'ES512',
        })

    def get_validate_key(self):
        with open(get_file_path('secp521r1-public.json'), 'r') as f:
            return json.load(f)


class PEMOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        jwt_key_path = get_file_path('rsa_private.pem')
        with open(jwt_key_path, 'r') as f:
            jwt_key = to_unicode(f.read())

        DUMMY_JWT_CONFIG.update({
            'iss': 'Authlib',
            'key': jwt_key,
            'alg': 'RS256',
        })

    def get_validate_key(self):
        with open(get_file_path('rsa_public.pem'), 'r') as f:
            return f.read()
