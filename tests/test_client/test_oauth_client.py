from __future__ import unicode_literals, print_function
import mock
import unittest
import requests
from authlib.common.urls import quote
from authlib.client import OAuthClient


class OAuthClientTest(unittest.TestCase):

    def test_oauth1_authorize_redirect(self):

        def verify_oauth1_redirect(uri, callback_uri, state):
            self.assertIsNone(state)
            self.assertIn('foo', uri)

        def request_token_setter(token):
            self.assertIn('oauth_token', token)

        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            authorize_url='https://a.com/auth'
        )
        client.session.send = self.fake_body('oauth_token=foo')
        client.register_hook('authorize_redirect', verify_oauth1_redirect)
        client.register_hook('request_token_setter', request_token_setter)
        client.authorize_redirect('https://b.com/bar')

    def test_oauth2_authorize_redirect(self):

        def verify_oauth2_redirect(uri, callback_uri, state):
            self.assertIn(state, uri)
            self.assertIn(quote(callback_uri, ''), uri)

        client = OAuthClient('foo', authorize_url='https://a.com/auth')
        client.register_hook('authorize_redirect', verify_oauth2_redirect)
        client.authorize_redirect('https://b.com/red')

    def test_authorize_redirect_errors(self):
        client = OAuthClient('foo', authorize_url='https://a.com/auth')
        self.assertRaises(AssertionError, client.authorize_redirect, '')

        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            authorize_url='https://a.com/auth'
        )

        client.register_hook('authorize_redirect', lambda: 'ok')
        self.assertRaises(AssertionError, client.authorize_redirect, '')

    def test_oauth1_fetch_access_token(self):
        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            access_token_url='https://example.com/token'
        )

        def request_token_getter():
            return {'oauth_token': 'req'}

        client.register_hook('request_token_getter', request_token_getter)
        client.session.send = self.fake_body('oauth_token=foo')
        resp = client.fetch_access_token(oauth_verifier='bar')
        self.assertEqual(resp['oauth_token'], 'foo')

    def test_oauth2_fetch_access_token(self):
        url = 'https://example.com/token'

        token = {
            'token_type': 'Bearer',
            'access_token': 'asdfoiw37850234lkjsdfsdf',
            'refresh_token': 'sldvafkjw34509s8dfsdf',
            'expires_in': '3600',
            'expires_at': 3600,
        }

        client = OAuthClient(client_id='foo', access_token_url=url)
        client.session.send = self.fake_token(token)
        self.assertEqual(client.fetch_access_token(), token)
        self.assertEqual(client.fetch_access_token(url), token)

    def fake_token(self, token):
        def fake_send(r, **kwargs):
            resp = mock.MagicMock()
            resp.json = lambda: token
            return resp
        return fake_send

    def fake_body(self, body, status_code=200):
        def fake_send(r, **kwargs):
            resp = mock.MagicMock(spec=requests.Response)
            resp.cookies = []
            resp.text = body
            resp.status_code = status_code
            return resp
        return fake_send
