from flask import json
from authlib.common.urls import urlparse, url_decode
from authlib.specs.rfc6749 import grants
from authlib.specs.rfc7636 import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    CodeChallenge as _CodeChallenge,
    create_s256_code_challenge,
)
from .models import db, User, Client
from .models import CodeGrantMixin, generate_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        return generate_authorization_code(
            client, grant_user, request,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )


class CodeChallenge(_CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ['plain', 'S256', 'S128']

    def get_authorization_code_challenge(self, authorization_code):
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        return authorization_code.code_challenge_method


class CodeChallengeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        return generate_authorization_code(
            client, grant_user, request,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    def get_authorization_code_challenge(self, authorization_code):
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        return authorization_code.code_challenge_method


class AuthorizationCodeTest(TestCase):
    def prepare_data(self, token_endpoint_auth_method='none'):

        server = create_authorization_server(self.app)
        server.register_grant(CodeChallengeGrant)

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client_secret = ''
        if token_endpoint_auth_method != 'none':
            client_secret = 'code-secret'

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret=client_secret,
            redirect_uri='https://a.b',
            scope='profile address',
            token_endpoint_auth_method=token_endpoint_auth_method,
            response_type='code',
            grant_type='authorization_code',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=code-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_missing_code_challenge(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url)
        self.assertIn(b'Missing', rv.data)

    def test_has_code_challenge(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url + '&code_challenge=abc')
        self.assertEqual(rv.data, b'ok')

    def test_invalid_code_challenge_method(self):
        self.prepare_data()
        suffix = '&code_challenge=abc&code_challenge_method=invalid'
        rv = self.client.get(self.authorize_url + suffix)
        self.assertIn(b'Unsupported', rv.data)

    def test_supported_code_challenge_method(self):
        self.prepare_data()
        suffix = '&code_challenge=abc&code_challenge_method=plain'
        rv = self.client.get(self.authorize_url + suffix)
        self.assertEqual(rv.data, b'ok')

    def test_trusted_client_without_code_challenge(self):
        self.prepare_data('client_secret_basic')
        rv = self.client.get(self.authorize_url)
        self.assertEqual(rv.data, b'ok')

        rv = self.client.post(self.authorize_url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))

        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)

    def test_missing_code_verifier(self):
        self.prepare_data()
        url = self.authorize_url + '&code_challenge=foo'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertIn('Missing', resp['error_description'])

    def test_trusted_client_missing_code_verifier(self):
        self.prepare_data('client_secret_basic')
        url = self.authorize_url + '&code_challenge=foo'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        headers = self.create_basic_header('code-client', 'code-secret')
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
        }, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn('Missing', resp['error_description'])

    def test_plain_code_challenge_failed(self):
        self.prepare_data()
        url = self.authorize_url + '&code_challenge=foo'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'code_verifier': 'bar',
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertIn('failed', resp['error_description'])

    def test_plain_code_challenge_success(self):
        self.prepare_data()
        url = self.authorize_url + '&code_challenge=foo'
        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'code_verifier': 'foo',
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)

    def test_s256_code_challenge_success(self):
        self.prepare_data()
        code_challenge = create_s256_code_challenge('foo')
        url = self.authorize_url + '&code_challenge=' + code_challenge
        url += '&code_challenge_method=S256'

        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        rv = self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'code_verifier': 'foo',
            'client_id': 'code-client',
        })
        resp = json.loads(rv.data)
        self.assertIn('access_token', resp)


class CodeChallengeTest(AuthorizationCodeTest):
    def prepare_data(self, token_endpoint_auth_method='none'):
        server = create_authorization_server(self.app)
        server.register_grant(
            AuthorizationCodeGrant,
            [CodeChallenge(required=True)]
        )

        user = User(username='foo')
        db.session.add(user)
        db.session.commit()

        client_secret = ''
        if token_endpoint_auth_method != 'none':
            client_secret = 'code-secret'

        client = Client(
            user_id=user.id,
            client_id='code-client',
            client_secret=client_secret,
            redirect_uri='https://a.b',
            scope='profile address',
            token_endpoint_auth_method=token_endpoint_auth_method,
            response_type='code',
            grant_type='authorization_code',
        )
        self.authorize_url = (
            '/oauth/authorize?response_type=code'
            '&client_id=code-client'
        )
        db.session.add(client)
        db.session.commit()

    def test_not_implemented_code_challenge_method(self):
        self.prepare_data()
        url = self.authorize_url + '&code_challenge=foo'
        url += '&code_challenge_method=S128'

        rv = self.client.post(url, data={'user_id': '1'})
        self.assertIn('code=', rv.location)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params['code']
        self.assertRaises(
            RuntimeError, self.client.post, '/oauth/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'code_verifier': 'foo',
                'client_id': 'code-client',
            }
        )
