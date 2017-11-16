from __future__ import unicode_literals, print_function
import unittest
from authlib.common.urls import quote
from authlib.client import OAuthClient, OAuthException
from ..client_base import (
    mock_json_response,
    mock_text_response,
    get_bearer_token,
)


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
        client.session.send = mock_text_response('oauth_token=foo')
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
        client.session.send = mock_text_response('oauth_token=foo')
        resp = client.fetch_access_token(oauth_verifier='bar')
        self.assertEqual(resp['oauth_token'], 'foo')

    def test_oauth2_fetch_access_token(self):
        url = 'https://example.com/token'
        token = get_bearer_token()
        client = OAuthClient(client_id='foo', access_token_url=url)
        client.session.send = mock_json_response(token)
        self.assertEqual(client.fetch_access_token(), token)
        self.assertEqual(client.fetch_access_token(url), token)

    def test_request_with_token_getter(self):
        client = OAuthClient(client_id='foo')
        client.session.send = mock_json_response({'name': 'a'})
        try:
            client.get('https://i.b/user')
        except AssertionError as exc:
            self.assertIn('missing', str(exc))

        client.register_hook('access_token_getter', lambda: None)
        try:
            client.get('https://i.b/user')
        except OAuthException as exc:
            self.assertEqual('token_missing', exc.type)

        client.register_hook('access_token_getter', get_bearer_token)
        resp = client.get('https://i.b/user')
        self.assertEqual(resp.json()['name'], 'a')
        resp = client.post('https://i.b/user')
        self.assertEqual(resp.json()['name'], 'a')
        resp = client.put('https://i.b/user')
        self.assertEqual(resp.json()['name'], 'a')
        resp = client.delete('https://i.b/user')
        self.assertEqual(resp.json()['name'], 'a')

        client.api_base_url = 'https://i.b'
        resp = client.get('user')
        self.assertEqual(resp.json()['name'], 'a')
