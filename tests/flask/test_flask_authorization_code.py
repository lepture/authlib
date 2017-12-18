from flask import json
from authlib.common.urls import urlparse, url_decode
from authlib.flask.oauth2 import register_cache_authorization_code
from .oauth2_server import db, User, Client, Token
from .oauth2_server import TestCase
from .oauth2_server import AuthorizationCodeGrant
from .oauth2_server import create_authorization_server


class AuthorizationCodeTest(TestCase):
    def register_grant_endpoint(self, server):
        server.register_grant_endpoint(AuthorizationCodeGrant)

    def prepare_data(self, is_confidential=True, response_types='code'):
        server = create_authorization_server(self.app)
        self.register_grant_endpoint(server)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret='code-secret',
            default_redirect_uri='https://a.b',
            allowed_scopes='profile address',
            is_confidential=is_confidential,
            allowed_response_types=response_types,
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=code-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_get_authorize(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'ok')

    def test_invalid_authorize(self):
        self.prepare_data()
        rv = self.client.post(self.authorize_url)
        self.assertIn('error=access_denied', rv.location)

        rv = self.client.post(self.authorize_url + '&scope=invalid&state=foo')
        self.assertIn('error=invalid_scope', rv.location)
        self.assertIn('state=foo', rv.location)

    def test_unauthorized_client(self):
        self.prepare_data(True, 'token')
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'error')

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
            'client_id': 'invalid-id',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

        headers = self.create_basic_header('code-client', 'invalid-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_client')

    def test_invalid_code(self):
        self.prepare_data()

        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': 'invalid',
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_invalid_redirect_uri(self):
        self.prepare_data()
        uri = self.authorize_url + '&redirect_uri=https%3A%2F%2Fa.c'
        rv = self.client.post(uri, data={'user_id': '1'})
        self.assertIn('error=invalid_request', rv.location)

        uri = self.authorize_url + '&redirect_uri=https%3A%2F%2Fa.b'
        rv = self.client.post(uri, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'invalid_request')

    def test_public_client(self):
        self.prepare_data(False)
        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertEqual(resp['error'], 'unauthorized_client')

    def test_public_authorize_token(self):
        self.app.config.update({'OAUTH2_REFRESH_TOKEN_GENERATOR': True})
        self.prepare_data(False)
        client = Client.query.filter_by(client_id='code-client').first()
        client.client_secret = ''
        db.session.add(client)
        db.session.commit()

        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertNotIn('refresh_token', resp)

    def test_authorize_token(self):
        # generate refresh token
        self.app.config.update({'OAUTH2_REFRESH_TOKEN_GENERATOR': True})
        self.prepare_data()
        url = self.authorize_url + '&state=bar'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        self.assertEqual(params['state'], 'bar')

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)
        self.assertIn('refresh_token', resp)


class CacheAuthorizationCodeTest(AuthorizationCodeTest):
    def register_grant_endpoint(self, server):
        self.app.config.update({'OAUTH2_CODE_CACHE_TYPE': 'simple'})

        def create_access_token(token, client, authorization_code):
            item = Token(
                client_id=client.client_id,
                user_id=authorization_code.user_id,
                **token
            )
            db.session.add(item)
            db.session.commit()
            # we can add more data into token
            token['user_id'] = authorization_code.user_id

        register_cache_authorization_code(
            self.app, server, create_access_token
        )
