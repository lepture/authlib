from flask import json
from .oauth2_server import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import PasswordGrant
from .oauth2_server import create_authorization_server


class PasswordTest(TestCase):
    def prepare_data(self):
        server = create_authorization_server(self.app)
        server.register_endpoint_grant(PasswordGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='password-client',
            client_secret='password-secret',
            default_redirect_uri='http://localhost/authorized',
            allowed_scopes='profile',
            is_confidential=True,
        )
        db.session.add(client)
        db.session.commit()

    def test_authorize_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'password-client', 'password-secret'
        )
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'password',
            'username': 'foo',
            'password': 'ok',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
