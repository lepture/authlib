from fastapi import Request, Form
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from .models import db, User, Client, Token
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


RevocationEndpoint = create_revocation_endpoint(db, Token)


class RevokeTokenTest(TestCase):
    def prepare_data(self):
        app = self.app
        server = create_authorization_server(app)
        server.register_endpoint(RevocationEndpoint)

        @app.post('/oauth/revoke')
        def revoke_token(request: Request,
                         token: str = Form(None),
                         token_type_hint: str = Form(None)):
            request.body = {}
            if token:
                request.body.update({'token': token})
            if token_type_hint:
                request.body.update({'token_type_hint': token_type_hint})
            return server.create_endpoint_response('revocation', request=request)

        user = User(username='foo')
        db.add(user)
        db.commit()
        client = Client(
            user_id=user.id,
            client_id='revoke-client',
            client_secret='revoke-secret',
        )
        client.set_client_metadata({
            'scope': 'profile',
            'redirect_uris': ['http://localhost/authorized'],
        })
        db.add(client)
        db.commit()

    def create_token(self):
        token = Token(
            user_id=1,
            client_id='revoke-client',
            token_type='bearer',
            access_token='a1',
            refresh_token='r1',
            scope='profile',
            expires_in=3600,
        )
        db.add(token)
        db.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/revoke')
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_client')

        headers = {'Authorization': 'invalid token_string'}
        rv = self.client.post('/oauth/revoke', headers=headers)
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'invalid-client', 'revoke-secret'
        )
        rv = self.client.post('/oauth/revoke', headers=headers)
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'revoke-client', 'invalid-secret'
        )
        rv = self.client.post('/oauth/revoke', headers=headers)
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_client')

    def test_invalid_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'revoke-client', 'revoke-secret'
        )
        rv = self.client.post('/oauth/revoke', headers=headers)
        resp = rv.json()
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/revoke', data={
            'token': 'invalid-token',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)

        rv = self.client.post('/oauth/revoke', data={
            'token': 'a1',
            'token_type_hint': 'unsupported_token_type',
        }, headers=headers)
        resp = rv.json()
        self.assertEqual(resp['error'], 'unsupported_token_type')

        rv = self.client.post('/oauth/revoke', data={
            'token': 'a1',
            'token_type_hint': 'refresh_token',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)

    def test_revoke_token_with_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'revoke-client', 'revoke-secret'
        )
        rv = self.client.post('/oauth/revoke', data={
            'token': 'a1',
            'token_type_hint': 'access_token',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)

    def test_revoke_token_without_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'revoke-client', 'revoke-secret'
        )
        rv = self.client.post('/oauth/revoke', data={
            'token': 'a1',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)
