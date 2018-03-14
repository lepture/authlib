from authlib.specs.rfc6749.grants import ImplicitGrant
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ImplicitTest(TestCase):
    def prepare_data(self, is_confidential=False, response_type='token'):
        server = create_authorization_server(self.app)
        server.register_grant(ImplicitGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        if is_confidential:
            client_secret = 'implicit-secret'
            token_endpoint_auth_method = 'client_secret_basic'
        else:
            client_secret = ''
            token_endpoint_auth_method = 'none'

        client = Client(
            user_id=user.id,
            client_id='implicit-client',
            client_secret=client_secret,
            redirect_uri='http://localhost/authorized',
            response_type=response_type,
            grant_type='implicit',
            scope='profile',
            token_endpoint_auth_method=token_endpoint_auth_method,
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=token'
            '&client_id=implicit-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_get_authorize(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'ok')

    def test_confidential_client(self):
        self.prepare_data(True)
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'invalid_client')

    def test_unsupported_client(self):
        self.prepare_data(response_type='code')
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'unauthorized_client')

    def test_invalid_authorize(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url)
        self.assertIn('error=access_denied', rv.location)

        rv = self.client.post(self.authorize_url + '&scope=invalid')
        self.assertIn('error=invalid_scope', rv.location)

    def test_authorize_token(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('access_token=', rv.location)

        url = self.authorize_url + '&state=bar&scope=profile'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('access_token=', rv.location)
        self.assertIn('state=bar', rv.location)
        self.assertIn('scope=profile', rv.location)
