from __future__ import unicode_literals, print_function
import unittest
import mock
from authlib.common.urls import quote
from authlib.client import OAuthClient, OAuthException
from ..client_base import (
    mock_json_response,
    mock_text_response,
    get_bearer_token,
)


class OAuthClientTest(unittest.TestCase):

    def test_oauth1_generate_authorize_redirect(self):
        def save_request_token(token):
            self.assertIn('oauth_token', token)

        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            authorize_url='https://a.com/auth'
        )
        client.session.send = mock_text_response('oauth_token=foo')
        uri, state = client.generate_authorize_redirect(
            'https://b.com/bar', save_request_token)
        self.assertIsNone(state)
        self.assertIn('oauth_token=foo', uri)

    def test_oauth1_realms(self):
        def save_request_token(token):
            self.assertIn('oauth_token', token)

        def fake_send(r, **kwargs):
            auth = r.headers['Authorization']
            self.assertIn('realm', auth)
            resp = mock.MagicMock()
            resp.cookies = []
            resp.text = 'oauth_token=foo'
            resp.status_code = 200
            return resp

        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            request_token_params={'realm': 'email'},
            authorize_url='https://a.com/auth'
        )

        client.session.send = fake_send
        uri, state = client.generate_authorize_redirect(
            'https://b.com/bar', save_request_token)
        self.assertIsNone(state)
        self.assertIn('oauth_token=foo', uri)

        client.request_token_params = {'realm': ['email', 'profile']}
        uri, state = client.generate_authorize_redirect(
            'https://b.com/bar', save_request_token)
        self.assertIsNone(state)
        self.assertIn('oauth_token=foo', uri)

    def test_oauth2_generate_authorize_redirect(self):
        callback_uri = 'https://b.com/red'
        client = OAuthClient('foo', authorize_url='https://a.com/auth')
        uri, state = client.generate_authorize_redirect(callback_uri)
        self.assertIn(state, uri)
        self.assertIn(quote(callback_uri, ''), uri)

    def test_oauth1_fetch_access_token(self):
        client = OAuthClient(
            'foo',
            request_token_url='https://a.com/req',
            access_token_url='https://example.com/token'
        )

        request_token = {'oauth_token': 'req'}

        client.session.send = mock_text_response('oauth_token=foo')
        resp = client.fetch_access_token(
            request_token=request_token, oauth_verifier='bar')
        self.assertEqual(resp['oauth_token'], 'foo')

    def test_oauth2_fetch_access_token(self):
        url = 'https://example.com/token'
        token = get_bearer_token()
        client = OAuthClient(client_id='foo', access_token_url=url)
        client.session.send = mock_json_response(token)
        self.assertEqual(client.fetch_access_token(), token)
        self.assertEqual(client.fetch_access_token(url), token)

    def test_request_without_token(self):
        class MyOAuthClient(OAuthClient):
            def get_token(self):
                return None

        client = MyOAuthClient(client_id='foo')
        client.session.send = mock_json_response({'name': 'a'})
        try:
            client.get('https://i.b/user')
        except OAuthException as exc:
            self.assertEqual('token_missing', exc.type)

    def test_request_with_token(self):
        class MyOAuthClient(OAuthClient):
            def get_token(self):
                return get_bearer_token()

        client = MyOAuthClient(client_id='foo')
        client.session.send = mock_json_response({'name': 'a'})
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
