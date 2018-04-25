from authlib.specs.rfc7519 import JWT
from authlib.specs.oidc import ImplicitIDToken
from authlib.specs.oidc.grants import OpenIDImplicitGrant
from authlib.common.urls import urlparse, url_decode
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ImplicitTest(TestCase):
    def prepare_data(self):
        self.app.config.update({
            'OAUTH2_JWT_ENABLED': True,
            'OAUTH2_JWT_ISS': 'Authlib',
            'OAUTH2_JWT_KEY': 'secret',
            'OAUTH2_JWT_ALG': 'HS256',
        })

        server = create_authorization_server(self.app)
        server.register_grant(OpenIDImplicitGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='implicit-client',
            client_secret='',
            redirect_uri='https://a.b/c',
            scope='openid profile',
            token_endpoint_auth_method='none',
            response_type='id_token\nid_token token',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=token'
            '&client_id=implicit-client'
        )
        db.session.add(client)
        db.session.commit()

    def validate_claims(self, id_token, params):
        jwt = JWT(['HS256'])
        claims = jwt.decode(
            id_token, 'secret',
            claims_cls=ImplicitIDToken,
            claims_params=params
        )
        claims.validate()

    def test_require_nonce(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'id_token',
            'client_id': 'implicit-client',
            'scope': 'openid profile',
            'state': 'bar',
            'redirect_uri': 'https://a.b/c',
            'user_id': '1'
        })
        self.assertIn('error=invalid_request', rv.location)
        self.assertIn('nonce', rv.location)

    def test_denied(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'id_token',
            'client_id': 'implicit-client',
            'scope': 'openid profile',
            'state': 'bar',
            'nonce': 'abc',
            'redirect_uri': 'https://a.b/c',
        })
        self.assertIn('error=access_denied', rv.location)

    def test_authorize_access_token(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'id_token token',
            'client_id': 'implicit-client',
            'scope': 'openid profile',
            'state': 'bar',
            'nonce': 'abc',
            'redirect_uri': 'https://a.b/c',
            'user_id': '1'
        })
        self.assertIn('access_token=', rv.location)
        self.assertIn('id_token=', rv.location)
        self.assertIn('state=bar', rv.location)
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.validate_claims(params['id_token'], params)

    def test_authorize_id_token(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'id_token',
            'client_id': 'implicit-client',
            'scope': 'openid profile',
            'state': 'bar',
            'nonce': 'abc',
            'redirect_uri': 'https://a.b/c',
            'user_id': '1'
        })
        self.assertIn('id_token=', rv.location)
        self.assertIn('state=bar', rv.location)
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.validate_claims(params['id_token'], params)

    def test_response_mode_query(self):
        self.prepare_data()
        rv = self.client.post('/oauth/authorize', data={
            'response_type': 'id_token',
            'response_mode': 'query',
            'client_id': 'implicit-client',
            'scope': 'openid profile',
            'state': 'bar',
            'nonce': 'abc',
            'redirect_uri': 'https://a.b/c',
            'user_id': '1'
        })
        self.assertIn('id_token=', rv.location)
        self.assertIn('state=bar', rv.location)
        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        self.validate_claims(params['id_token'], params)
