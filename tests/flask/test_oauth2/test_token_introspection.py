from flask import json
from authlib.flask.oauth2.sqla import create_query_token_func
from authlib.specs.rfc7662 import IntrospectionEndpoint
from .oauth2_server import db, User, Client, Token
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


query_token = create_query_token_func(db.session, Token)


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def query_token(self, token, token_type_hint, client):
        return query_token(token, token_type_hint, client)

    def introspect_token(self, token):
        user = User.query.get(token.user_id)
        return {
            "active": not token.revoked,
            "client_id": token.client_id,
            "username": user.username,
            "scope": token.scope,
            "sub": user.get_user_id(),
            "aud": token.client_id,
            "iss": "https://server.example.com/",
            "exp": token.get_expires_at(),
            "iat": token.issued_at,
        }


class IntrospectTokenTest(TestCase):
    def prepare_data(self):
        server = create_authorization_server(self.app)
        server.register_endpoint(MyIntrospectionEndpoint)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='introspect-client',
            client_secret='introspect-secret',
            redirect_uri='http://a.b/c',
            scope='profile',
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self):
        token = Token(
            user_id=1,
            client_id='introspect-client',
            token_type='bearer',
            access_token='a1',
            refresh_token='r1',
            scope='profile',
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/introspect')
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = {'Authorization': 'invalid token_string'}
        rv = self.client.post('/oauth/introspect', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'invalid-client', 'introspect-secret'
        )
        rv = self.client.post('/oauth/introspect', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header(
            'introspect-client', 'invalid-secret'
        )
        rv = self.client.post('/oauth/introspect', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

    def test_invalid_token(self):
        self.prepare_data()
        headers = self.create_basic_header(
            'introspect-client', 'introspect-secret'
        )
        rv = self.client.post('/oauth/introspect', headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/introspect', data={
            'token_type_hint': 'refresh_token',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/introspect', data={
            'token': 'a1',
            'token_type_hint': 'unsupported_token_type',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'unsupported_token_type')

        rv = self.client.post('/oauth/introspect', data={
            'token': 'invalid-token',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['active'], False)

        rv = self.client.post('/oauth/introspect', data={
            'token': 'a1',
            'token_type_hint': 'refresh_token',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['active'], False)

    def test_introspect_token_with_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'introspect-client', 'introspect-secret'
        )
        rv = self.client.post('/oauth/introspect', data={
            'token': 'a1',
            'token_type_hint': 'access_token',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)
        resp = json.loads(rv.data)
        self.assertEqual(resp['client_id'], 'introspect-client')

    def test_introspect_token_without_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header(
            'introspect-client', 'introspect-secret'
        )
        rv = self.client.post('/oauth/introspect', data={
            'token': 'a1',
        }, headers=headers)
        self.assertEqual(rv.status_code, 200)
        resp = json.loads(rv.data)
        self.assertEqual(resp['client_id'], 'introspect-client')
