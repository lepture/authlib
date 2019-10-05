from flask import json
from authlib.jose import jwt
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint as _ClientRegistrationEndpoint
from tests.util import read_file_path
from .models import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
    software_statement_alg_values_supported = ['RS256']

    def authenticate_user(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            return User.query.get(1)

    def resolve_public_key(self, request):
        return read_file_path('rsa_public.pem')

    def save_client(self, client_info, client_metadata, user):
        client = Client(
            user_id=user.id,
            **client_info
        )
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        return client


class ClientRegistrationTest(TestCase):
    def prepare_data(self, endpoint_cls=None, metadata=None):
        app = self.app
        server = create_authorization_server(app)
        if metadata:
            server.metadata = metadata

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

    def test_create_client(self):
        self.prepare_data()
        headers = {'Authorization': 'bearer abc'}
        body = {
            'client_name': 'Authlib'
        }
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

    def test_software_statement(self):
        payload = {'software_id': 'uuid-123', 'client_name': 'Authlib'}
        s = jwt.encode({'alg': 'RS256'}, payload, read_file_path('rsa_private.pem'))
        body = {
            'software_statement': s.decode('utf-8'),
        }

        self.prepare_data()
        headers = {'Authorization': 'bearer abc'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

    def test_no_public_key(self):

        class ClientRegistrationEndpoint2(ClientRegistrationEndpoint):
            def resolve_public_key(self, request):
                return None

        payload = {'software_id': 'uuid-123', 'client_name': 'Authlib'}
        s = jwt.encode({'alg': 'RS256'}, payload, read_file_path('rsa_private.pem'))
        body = {
            'software_statement': s.decode('utf-8'),
        }

        self.prepare_data(ClientRegistrationEndpoint2)
        headers = {'Authorization': 'bearer abc'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn(resp['error'], 'unapproved_software_statement')

    def test_scopes_supported(self):
        metadata = {'scopes_supported': ['profile', 'email']}
        self.prepare_data(metadata=metadata)

        headers = {'Authorization': 'bearer abc'}
        body = {'scope': 'profile email', 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

        body = {'scope': 'profile email address', 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn(resp['error'], 'invalid_client_metadata')

    def test_response_types_supported(self):
        metadata = {'response_types_supported': ['code']}
        self.prepare_data(metadata=metadata)

        headers = {'Authorization': 'bearer abc'}
        body = {'response_types': ['code'], 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

        body = {'response_types': ['code', 'token'], 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn(resp['error'], 'invalid_client_metadata')

    def test_grant_types_supported(self):
        metadata = {'grant_types_supported': ['authorization_code', 'password']}
        self.prepare_data(metadata=metadata)

        headers = {'Authorization': 'bearer abc'}
        body = {'grant_types': ['password'], 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

        body = {'grant_types': ['client_credentials'], 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn(resp['error'], 'invalid_client_metadata')

    def test_token_endpoint_auth_methods_supported(self):
        metadata = {'token_endpoint_auth_methods_supported': ['client_secret_basic']}
        self.prepare_data(metadata=metadata)

        headers = {'Authorization': 'bearer abc'}
        body = {'token_endpoint_auth_method': 'client_secret_basic', 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('client_id', resp)
        self.assertEqual(resp['client_name'], 'Authlib')

        body = {'token_endpoint_auth_method': 'none', 'client_name': 'Authlib'}
        rv = self.client.post('/create_client', json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn(resp['error'], 'invalid_client_metadata')
