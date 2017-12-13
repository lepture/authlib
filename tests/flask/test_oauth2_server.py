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
            client_id='test-code',
            client_secret='code-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile address',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=test-code'
        )
        db.session.add(client)
        db.session.commit()

    def test_get_authorize(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'ok')

    def test_post_authorize(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url)
        self.assertIn('error=access_denied', rv.location)

        rv = self.client.post(self.authorize_url + '&scope=invalid')
        self.assertIn('error=invalid_scope', rv.location)

        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)
