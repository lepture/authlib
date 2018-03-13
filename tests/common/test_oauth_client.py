from __future__ import unicode_literals, print_function
import unittest
import mock
from authlib.common.urls import quote
from authlib.client import OAuthClient, OAuthException
from ..client_base import (
    mock_send_value,
    get_bearer_token,
)


class OAuthClientTest(unittest.TestCase):

    def test_oauth1_generate_authorize_redirect(self):
        def save_request_token(token):
            self.assertIn('oauth_token', token)

        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value('oauth_token=foo')
            client = OAuthClient(
                'foo',
                request_token_url='https://a.com/req',
                authorize_url='https://a.com/auth'
            )
            uri, state = client.generate_authorize_redirect(
                'https://b.com/bar', save_request_token)
            self.assertIsNone(state)
            self.assertIn('oauth_token=foo', uri)

    def test_oauth1_realms(self):
        def save_request_token(token):
            self.assertIn('oauth_token', token)

        def fake_send(sess, req, **kwargs):
            auth = req.headers['Authorization']
            self.assertIn('realm', auth)
            resp = mock.MagicMock()
            resp.cookies = []
            resp.text = 'oauth_token=foo'
            resp.status_code = 200
            return resp

        with mock.patch('requests.sessions.Session.send', fake_send):
            client = OAuthClient(
                'foo',
                request_token_url='https://a.com/req',
                request_token_params={'realm': 'email'},
                authorize_url='https://a.com/auth'
            )

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
        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value('oauth_token=foo')
            client = OAuthClient(
                'foo',
                request_token_url='https://a.com/req',
                access_token_url='https://example.com/token'
            )

            request_token = {'oauth_token': 'req'}
            resp = client.fetch_access_token(
                request_token=request_token, oauth_verifier='bar')
            self.assertEqual(resp['oauth_token'], 'foo')

    def test_oauth2_fetch_access_token(self):
        url = 'https://example.com/token'
        token = get_bearer_token()
        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value(token)
            client = OAuthClient(client_id='foo', access_token_url=url)
            self.assertEqual(client.fetch_access_token(), token)
            self.assertEqual(client.fetch_access_token(url), token)

    def test_request_without_token(self):
        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value({'name': 'a'})
            client = OAuthClient(client_id='foo')
            try:
                client.get('https://i.b/user')
            except OAuthException as exc:
                self.assertEqual('token_missing', exc.type)

    def test_request_with_token(self):
        with mock.patch('requests.sessions.Session.send') as send:
            send.return_value = mock_send_value({'name': 'a'})

            client = OAuthClient(client_id='foo')
            token = get_bearer_token()
            resp = client.get('https://i.b/user', token=token)
            self.assertEqual(resp.json()['name'], 'a')

            resp = client.post('https://i.b/user', token=token)
            self.assertEqual(resp.json()['name'], 'a')

            resp = client.put('https://i.b/user', token=token)
            self.assertEqual(resp.json()['name'], 'a')

            resp = client.delete('https://i.b/user', token=token)
            self.assertEqual(resp.json()['name'], 'a')

            client.api_base_url = 'https://i.b'
            resp = client.get('user', token=token)
            self.assertEqual(resp.json()['name'], 'a')
