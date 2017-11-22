from __future__ import unicode_literals, print_function

from django.conf import settings
from django.utils.module_loading import import_module
from django.test import TestCase, RequestFactory, override_settings
from authlib.client.django import OAuth, RemoteApp
from ..client_base import (
    mock_text_response,
    mock_json_response,
    get_bearer_token
)

dev_client = {
    'client_key': 'dev-key',
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
            client_key='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize'
        )
        self.assertEqual(oauth.dev.name, 'dev')
        self.assertEqual(oauth.dev.client_key, 'dev')

    @override_settings(AUTHLIB_OAUTH_CLIENTS={'dev': dev_client})
    def test_register_from_settings(self):
        oauth = OAuth()
        oauth.register('dev')
        self.assertEqual(oauth.dev.client_key, 'dev-key')
        self.assertEqual(oauth.dev.client_secret, 'dev-secret')

    def test_oauth1_authorize(self):
        request = self.factory.get('/login')
        request.session = self.factory.session

        client = RemoteApp(
            'dev',
            client_key='dev',
            client_secret='dev',
            request_token_url='https://i.b/reqeust-token',
            base_url='https://i.b/api',
            access_token_url='https://i.b/token',
            authorize_url='https://i.b/authorize',
        )
        client.session.send = mock_text_response(
            'oauth_token=foo&oauth_verifier=baz'
        )
        resp = client.authorize_redirect(request)
        self.assertEqual(resp.status_code, 302)
        url = resp.get('Location')
        self.assertIn('oauth_token=foo', url)

        client.session.send = mock_text_response(
            'oauth_token=a&oauth_token_secret=b'
        )
        token = client.authorize_access_token(request)
        self.assertEqual(token['oauth_token'], 'a')

    def test_oauth2_authorize(self):
        request = self.factory.get('/login')
        request.session = self.factory.session

        client = RemoteApp(
            'dev',
            client_key='dev',
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

        client.session.send = mock_json_response(get_bearer_token())
        request = self.factory.get('/authorize?state={}'.format(state))
        request.session = self.factory.session
        request.session['_dev_state_'] = state

        token = client.authorize_access_token(request)
        self.assertEqual(token['access_token'], 'a')
