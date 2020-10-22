import time
from fastapi import Request, Form
from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
    DeviceCodeGrant as _DeviceCodeGrant,
    DeviceCredentialDict,
)
from .models import db, User, Client
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


device_credentials = {
    'valid-device': {
        'client_id': 'client',
        'expires_in': 1800,
        'user_code': 'code',
    },
    'expired-token': {
        'client_id': 'client',
        'expires_in': -100,
        'user_code': 'none',
    },
    'invalid-client': {
        'client_id': 'invalid',
        'expires_in': 1800,
        'user_code': 'none',
    },
    'denied-code': {
        'client_id': 'client',
        'expires_in': 1800,
        'user_code': 'denied',
    },
    'grant-code': {
        'client_id': 'client',
        'expires_in': 1800,
        'user_code': 'code',
    },
    'pending-code': {
        'client_id': 'client',
        'expires_in': 1800,
        'user_code': 'none',
    }
}

class DeviceCodeGrant(_DeviceCodeGrant):
    def query_device_credential(self, device_code):
        data = device_credentials.get(device_code)
        if not data:
            return None

        now = int(time.time())
        data['expires_at'] = now + data['expires_in']
        data['device_code'] = device_code
        data['scope'] = 'profile'
        data['interval'] = 5
        data['verification_uri'] = 'https://example.com/activate'
        return DeviceCredentialDict(data)

    def query_user_grant(self, user_code):
        if user_code == 'code':
            return db.query(User).filter(User.id == 1).first(), True
        if user_code == 'denied':
            return db.query(User).filter(User.id == 1).first(), False
        return None

    def should_slow_down(self, credential, now):
        return False


class DeviceCodeGrantTest(TestCase):
    def create_server(self):
        server = create_authorization_server(self.app)
        server.register_grant(DeviceCodeGrant)
        self.server = server
        return server

    def prepare_data(self, grant_type=DeviceCodeGrant.GRANT_TYPE):
        user = User(username='foo')
        db.add(user)
        db.commit()
        client = Client(
            user_id=user.id,
            client_id='client',
            client_secret='secret',
        )
        client.set_client_metadata({
            'redirect_uris': ['http://localhost/authorized'],
            'scope': 'profile',
            'grant_types': [grant_type],
        })
        db.add(client)
        db.commit()

    def test_invalid_request(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'valid-device',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'missing',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_request')

    def test_unauthorized_client(self):
        self.create_server()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'valid-device',
            'client_id': 'invalid',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'unauthorized_client')

        self.prepare_data(grant_type='password')
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'valid-device',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'unauthorized_client')

    def test_invalid_client(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'invalid-client',
            'client_id': 'invalid',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_client')

    def test_expired_token(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'expired-token',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'expired_token')

    def test_denied_by_user(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'denied-code',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'access_denied')

    def test_authorization_pending(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'pending-code',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertEqual(resp['error'], 'authorization_pending')

    def test_get_access_token(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': DeviceCodeGrant.GRANT_TYPE,
            'device_code': 'grant-code',
            'client_id': 'client',
        })
        resp = rv.json()
        self.assertIn('access_token', resp)


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return 'https://example.com/activate'

    def save_device_credential(self, client_id, scope, data):
        pass


class DeviceAuthorizationEndpointTest(TestCase):
    def create_server(self):
        server = create_authorization_server(self.app)
        server.register_endpoint(DeviceAuthorizationEndpoint)
        self.server = server

        @self.app.post('/device_authorize')
        def device_authorize(request: Request,
                             scope: str = Form(None),
                             client_id: str = Form(None)):
            request.body = {
                'scope': scope,
                'client_id': client_id,
            }
            name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
            return server.create_endpoint_response(name, request=request)

        return server

    def test_missing_client_id(self):
        self.create_server()
        rv = self.client.post('/device_authorize', data={
            'scope': 'profile'
        })
        self.assertEqual(rv.status_code, 400)
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_request')

    def test_create_authorization_response(self):
        self.create_server()
        rv = self.client.post('/device_authorize', data={
            'client_id': 'client',
        })
        self.assertEqual(rv.status_code, 200)
        resp = rv.json()
        self.assertIn('device_code', resp)
        self.assertIn('user_code', resp)
        self.assertEqual(resp['verification_uri'], 'https://example.com/activate')
        self.assertEqual(
            resp['verification_uri_complete'],
            'https://example.com/activate?user_code=' + resp['user_code']
        )
