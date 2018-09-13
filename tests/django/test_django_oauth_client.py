from __future__ import unicode_literals, print_function

import mock
from django.test import override_settings
from authlib.django.client import OAuth, RemoteApp
from .base import TestCase
from ..client_base import (
    mock_send_value,
    get_bearer_token
)

dev_client = {
    'client_id': 'dev-key',
    'client_secret': 'dev-secret'
}


class DjangoOAuthTest(TestCase):
    def test_register_remote_app(self):
        oauth = OAuth()
        self.assertRaises(AttributeError, lambda: oauth.dev)

        oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_id, 'dev')

    def test_register_with_overwrite(self):
        oauth = OAuth()
        oauth.register(
            'dev_overwrite',
            overwrite=True,
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            access_token_params={
                'foo': 'foo'
            },
            authorize_url='https://i.b/authorize'
        )
        self.assertEqual(oauth.dev_overwrite.client_id, 'dev-client-id')
        self.assertEqual(
            oauth.dev_overwrite.access_token_params['foo'], 'foo-1')

    @override_settings(AUTHLIB_OAUTH_CLIENTS={'dev': dev_client})
    def test_register_from_settings(self):
        oauth = OAuth()
        oauth.register('dev')
        self.assertEqual(oauth.dev.client_id, 'dev-key')
        self.assertEqual(oauth.dev.client_secret, 'dev-secret')

    def test_oauth1_authorize(self):
        request = self.factory.get('/login')
        request.session = self.factory.session

        client = RemoteApp(
            'dev',
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value('oauth_token=foo&oauth_verifier=baz')

            resp = client.authorize_redirect(request)
            self.assertEqual(resp.status_code, 302)
            url = resp.get('Location')
            self.assertIn('oauth_token=foo', url)

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value('oauth_token=a&oauth_token_secret=b')
            token = client.authorize_access_token(request)
            self.assertEqual(token['oauth_token'], 'a')

    def test_oauth2_authorize(self):
        request = self.factory.get('/login')
        request.session = self.factory.session

        client = RemoteApp(
            'dev',
            client_id='dev',
            client_secret='dev',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )
        rv = client.authorize_redirect(request, 'https://a.b/c')
        self.assertEqual(rv.status_code, 302)
        url = rv.get('Location')
        self.assertIn('state=', url)
        state = request.session['_dev_authlib_state_']

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value(get_bearer_token())
            request = self.factory.get('/authorize?state={}'.format(state))
            request.session = self.factory.session
            request.session['_dev_authlib_state_'] = state

            token = client.authorize_access_token(request)
            self.assertEqual(token['access_token'], 'a')

    def test_oauth2_authorize_code_challenge(self):
        request = self.factory.get('/login')
        request.session = self.factory.session

        client = RemoteApp(
            'dev',
            client_id='dev',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
            code_challenge_method='S256',
        )
        rv = client.authorize_redirect(request, 'https://a.b/c')
        self.assertEqual(rv.status_code, 302)
        url = rv.get('Location')
        self.assertIn('state=', url)
        self.assertIn('code_challenge=', url)
        state = request.session['_dev_authlib_state_']
        verifier = request.session['_dev_authlib_code_verifier_']

        def fake_send(sess, req, **kwargs):
            self.assertIn('code_verifier={}'.format(verifier), req.body)
            return mock_send_value(get_bearer_token())

        with mock.patch('requests.sessions.Session.send', fake_send):
            request = self.factory.get('/authorize?state={}'.format(state))
            request.session = self.factory.session
            request.session['_dev_authlib_state_'] = state
            request.session['_dev_authlib_code_verifier_'] = verifier

            token = client.authorize_access_token(request)
            self.assertEqual(token['access_token'], 'a')

    def test_oauth2_access_token_with_post(self):
        client = RemoteApp(
            'dev',
            client_id='dev',
            client_secret='dev',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )
        payload = {'code': 'a', 'state': 'b'}

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value(get_bearer_token())
            request = self.factory.post('/token', data=payload)
            request.session = self.factory.session
            request.session['_dev_authlib_state_'] = 'b'
            token = client.authorize_access_token(request)
            self.assertEqual(token['access_token'], 'a')

    def test_with_fetch_token_in_oauth(self):
        def fetch_token(name, request):
            return {'access_token': name, 'token_type': 'bearer'}

        oauth = OAuth(fetch_token)
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )

        def fake_send(sess, req, **kwargs):
            self.assertEqual(sess.token['access_token'], 'dev')
            return mock_send_value(get_bearer_token())

        with mock.patch('requests.sessions.Session.send', fake_send):
            request = self.factory.get('/login')
            client.get('/user', request=request)

    def test_with_fetch_token_in_register(self):
        def fetch_token(request):
            return {'access_token': 'dev', 'token_type': 'bearer'}

        oauth = OAuth()
        client = oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            api_base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
            fetch_token=fetch_token,
        )

        def fake_send(sess, req, **kwargs):
            self.assertEqual(sess.token['access_token'], 'dev')
            return mock_send_value(get_bearer_token())

        with mock.patch('requests.sessions.Session.send', fake_send):
            request = self.factory.get('/login')
            client.get('/user', request=request)
