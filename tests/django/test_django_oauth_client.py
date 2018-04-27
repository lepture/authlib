from __future__ import unicode_literals, print_function

import mock
from django.conf import settings
from django.utils.module_loading import import_module
from django.test import TestCase, RequestFactory, override_settings
from authlib.django.client import OAuth, RemoteApp
from ..client_base import (
    mock_send_value,
    get_bearer_token
)

dev_client = {
    'client_id': 'dev-key',
    'client_secret': 'dev-secret'
}


class RequestClient(RequestFactory):
    @property
    def session(self):
        engine = import_module(settings.SESSION_ENGINE)
        cookie = self.cookies.get(settings.SESSION_COOKIE_NAME)
        if cookie:
            return engine.SessionStore(cookie.value)

        session = engine.SessionStore()
        session.save()
        self.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
        return session


class DjangoOAuthTest(TestCase):
    def setUp(self):
        self.factory = RequestClient()

    def test_register_remote_app(self):
        oauth = OAuth()
        self.assertRaises(AttributeError, lambda: oauth.dev)

        oauth.register(
            'dev',
            client_id='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
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
            base_url='https://i.b/api',
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
            base_url='https://i.b/api',
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
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )
        rv = client.authorize_redirect(request, 'https://a.b/c')
        self.assertEqual(rv.status_code, 302)
        url = rv.get('Location')
        self.assertIn('state=', url)
        state = request.session['_dev_state_']

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value(get_bearer_token())
            request = self.factory.get('/authorize?state={}'.format(state))
            request.session = self.factory.session
            request.session['_dev_state_'] = state

            token = client.authorize_access_token(request)
            self.assertEqual(token['access_token'], 'a')

    def test_oauth2_access_token_with_post(self):
        client = RemoteApp(
            'dev',
            client_id='dev',
            client_secret='dev',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )
        payload = {'code': 'a', 'state': 'b'}

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value(get_bearer_token())
            request = self.factory.post('/token', data=payload)
            request.session = self.factory.session
            request.session['_dev_state_'] = 'b'
            token = client.authorize_access_token(request)
            self.assertEqual(token['access_token'], 'a')
