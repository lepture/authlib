from authlib.specs.oidc.grants import OpenIDImplicitGrant
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
            redirect_uris='https://a.b/c',
            scope='openid profile',
            allowed_response_types='token id_token',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=token'
            '&client_id=implicit-client'
        )
        db.session.add(client)
        db.session.commit()

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
