from __future__ import unicode_literals
import mock
import time
from copy import deepcopy
from unittest import TestCase

from authlib.common.urls import url_encode
from authlib.client import OAuth2Session
from authlib.specs.rfc6749 import OAuth2Error, MismatchingStateError


fake_time = int(time.time())


def fake_token(token):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: token
        return resp
    return fake_send


class OAuth2SessionTest(TestCase):

    def setUp(self):
        # For python 2.6
        if not hasattr(self, 'assertIn'):
            self.assertIn = lambda a, b: self.assertTrue(a in b)

        self.token = {
            'token_type': 'Bearer',
            'access_token': 'asdfoiw37850234lkjsdfsdf',
            'refresh_token': 'sldvafkjw34509s8dfsdf',
            'expires_in': '3600',
            'expires_at': fake_time + 3600,
        }
        self.client_id = 'foo'

    def test_add_token(self):
        token = 'Bearer ' + self.token['access_token']

        def verifier(r, **kwargs):
            auth_header = r.headers.get(str('Authorization'), None)
            self.assertEqual(auth_header, token)
            resp = mock.MagicMock()
            resp.cookes = []
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = verifier
        sess.get('https://i.b')

    def test_authorization_url(self):
        url = 'https://example.com/authorize?foo=bar'

        sess = OAuth2Session(client_id=self.client_id)
        auth_url, state = sess.authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn('response_type=code', auth_url)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_token_from_fragment(self):
        sess = OAuth2Session(self.client_id)
        response_url = 'https://i.b/callback#' + url_encode(self.token.items())
        self.assertEqual(sess.token_from_fragment(response_url), self.token)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_fetch_token(self):
        url = 'https://example.com/token'

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = fake_token(self.token)
        self.assertEqual(sess.fetch_token(url), self.token)

        error = {'error': 'invalid_request'}
        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = fake_token(error)
        self.assertRaises(OAuth2Error, sess.fetch_token, url)

    def test_cleans_previous_token_before_fetching_new_one(self):
        """Makes sure the previous token is cleaned before fetching a new one.
        The reason behind it is that, if the previous token is expired, this
        method shouldn't fail with a TokenExpiredError, since it's attempting
        to get a new one (which shouldn't be expired).
        """
        new_token = deepcopy(self.token)
        past = time.time() - 7200
        now = time.time()
        self.token['expires_at'] = past
        new_token['expires_at'] = now + 3600
        url = 'https://example.com/token'

        with mock.patch('time.time', lambda: now):
            sess = OAuth2Session(client_id=self.client_id, token=self.token)
            sess.send = fake_token(new_token)
            self.assertEqual(sess.fetch_token(url), new_token)

    def test_mis_match_state(self):
        # Ensure the state parameter is used, see issue #105.
        client = OAuth2Session('foo', state='somestate')
        self.assertRaises(
            MismatchingStateError,
            client.fetch_token,
            'https://i.b/token',
            authorization_response='https://i.b/no-state?code=abc'
        )
