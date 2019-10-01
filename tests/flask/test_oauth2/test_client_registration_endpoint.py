from flask import json
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint
from .models import db, User
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
    def authenticate_user(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            return User.query.get(1)

    def resolve_public_key(self, request):
        return b'hello'

    def save_client(self, client_info, client_metadata, user):
        return


class ClientRegistrationTest(TestCase):
    def prepare_data(self, endpoint_cls=None):
        app = self.app
        server = create_authorization_server(app)
        if endpoint_cls is None:
            endpoint_cls = ClientRegistrationEndpoint
        server.register_endpoint(endpoint_cls)

        @app.route('/create_client', methods=['POST'])
        def create_client():
            return server.create_endpoint_response('client_registration')

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

    def test_access_denied(self):
        self.prepare_data()
        rv = self.client.post('/create_client')
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'access_denied')

    def test_invalid_request(self):
        self.prepare_data()
        headers = {'Authorization': 'bearer abc'}
        rv = self.client.post('/create_client', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')
