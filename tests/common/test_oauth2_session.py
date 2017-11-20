from __future__ import unicode_literals
import mock
import time
from copy import deepcopy
from unittest import TestCase

from authlib.common.urls import url_encode
from authlib.client import OAuth2Session
from authlib.specs.rfc6749 import (
    OAuth2Error,
    MismatchingStateError,
)
from authlib.specs.rfc6750 import ExpiredTokenError
from ..client_base import mock_json_response


fake_time = int(time.time())


class OAuth2SessionTest(TestCase):

    def setUp(self):
        self.token = {
            'token_type': 'Bearer',
            'access_token': 'a',
            'refresh_token': 'b',
            'expires_in': '3600',
            'expires_at': fake_time + 3600,
        }
        self.client_id = 'foo'

    def test_add_token_to_header(self):
        token = 'Bearer ' + self.token['access_token']

        def verifier(r, **kwargs):
            auth_header = r.headers.get(str('Authorization'), None)
            self.assertEqual(auth_header, token)
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = verifier
        sess.get('https://i.b')

    def test_add_token_to_body(self):
        def verifier(r, **kwargs):
            self.assertIn(self.token['access_token'], r.body)
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(
            client_id=self.client_id,
            token=self.token,
            token_placement='body'
        )
        sess.send = verifier
        sess.post('https://i.b')

    def test_add_token_to_uri(self):
        def verifier(r, **kwargs):
            self.assertIn(self.token['access_token'], r.url)
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(
            client_id=self.client_id,
            token=self.token,
            token_placement='uri'
        )
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
        token = sess.fetch_access_token(authorization_response=response_url)
        self.assertEqual(token, self.token)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_fetch_token(self):
        url = 'https://example.com/token'

        def fake_send(r, **kwargs):
            self.assertIn('code=v', r.body)
            resp = mock.MagicMock()
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = fake_send
        self.assertEqual(sess.fetch_access_token(url, code='v'), self.token)
        self.assertEqual(
            sess.fetch_access_token(
                url, authorization_response='https://i.b/?code=v'),
            self.token)

        error = {'error': 'invalid_request'}
        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = mock_json_response(error)
        self.assertRaises(OAuth2Error, sess.fetch_access_token, url)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_access_token_response_hook(self):
        url = 'https://example.com/token'

        def access_token_response_hook(resp):
            self.assertEqual(resp.json(), self.token)
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.register_compliance_hook(
            'access_token_response',
            access_token_response_hook
        )
        sess.send = mock_json_response(self.token)
        self.assertEqual(sess.fetch_access_token(url), self.token)

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
            sess.send = mock_json_response(new_token)
            self.assertEqual(sess.fetch_access_token(url), new_token)

    def test_mis_match_state(self):
        sess = OAuth2Session('foo', state='somestate')
        self.assertRaises(
            MismatchingStateError,
            sess.fetch_token,
            'https://i.b/token',
            authorization_response='https://i.b/no-state?code=abc'
        )

    def test_token_status(self):
        sess = OAuth2Session('foo')
        self.assertIsNone(sess.token_cls)

        token = dict(access_token='a', token_type='bearer', expires_at=100)
        sess = OAuth2Session('foo', token=token)

        self.assertIsNotNone(sess.token_cls)
        self.assertTrue(sess.token.is_expired)

    def test_token_expired(self):
        token = dict(access_token='a', token_type='bearer', expires_at=100)
        sess = OAuth2Session('foo', token=token)
        self.assertRaises(
            ExpiredTokenError,
            sess.get,
            'https://i.b/token',
        )

    def test_register_compliance_hook(self):
        sess = OAuth2Session('foo')
        self.assertRaises(
            ValueError,
            sess.register_compliance_hook,
            'invalid_hook',
            lambda o: o,
        )

        def protected_request(url, headers, data):
            self.assertIn('Authorization', headers)
            return url, headers, data

        sess = OAuth2Session('foo', token=self.token)
        sess.register_compliance_hook(
            'protected_request',
            protected_request,
        )
        sess.send = mock_json_response({'name': 'a'})
        sess.get('https://i.b/user')

    def test_auto_refresh_token(self):

        def token_updater(token):
            self.assertEqual(token, self.token)

        old_token = dict(
            access_token='a', refresh_token='b',
            token_type='bearer', expires_at=100
        )
        sess = OAuth2Session(
            'foo', token=old_token,
            refresh_token_url='https://i.b/token',
            refresh_token_params={'ping': 'pong'},
            token_updater=token_updater,
        )
        sess.send = mock_json_response(self.token)
        sess.get('https://i.b/user')

    def test_revoke_token(self):
        sess = OAuth2Session('a')
        answer = {'status': 'ok'}
        sess.send = mock_json_response(answer)
        resp = sess.revoke_token('https://i.b/token', 'hi')
        self.assertEqual(resp.json(), answer)
