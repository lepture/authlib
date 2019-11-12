import mock
import time
from copy import deepcopy
from unittest import TestCase
from authlib.common.security import generate_token
from authlib.common.urls import url_encode
from authlib.integrations.httpx_client import (
    OAuthError,
    OAuth2Client,
)
from tests.py3.utils import MockDispatch


class OAuth2ClientTest(TestCase):
    def setUp(self):
        self.token = {
            'token_type': 'Bearer',
            'access_token': 'a',
            'refresh_token': 'b',
            'expires_in': '3600',
            'expires_at': int(time.time()) + 3600,
        }
        self.client_id = 'foo'

    def test_invalid_token_type(self):
        token = {
            'token_type': 'invalid',
            'access_token': 'a',
            'refresh_token': 'b',
            'expires_in': '3600',
            'expires_at': int(time.time()) + 3600,
        }
        with OAuth2Client(self.client_id, token=token) as client:
            self.assertRaises(OAuthError, client.get, 'https://i.b')

    def test_add_token_to_header(self):
        def assert_func(request):
            token = 'Bearer ' + self.token['access_token']
            auth_header = request.headers.get('authorization')
            self.assertEqual(auth_header, token)

        mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
        with OAuth2Client(self.client_id, token=self.token, dispatch=mock_response) as client:
            resp = client.get('https://i.b')

        data = resp.json()
        self.assertEqual(data['a'], 'a')

    def test_add_token_to_body(self):
        def assert_func(request):
            self.assertIn(self.token['access_token'], request.content.decode())

        mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
        with OAuth2Client(
                self.client_id,
                token=self.token,
                token_placement='body',
                dispatch=mock_response
        ) as client:
            resp = client.get('https://i.b')

        data = resp.json()
        self.assertEqual(data['a'], 'a')

    def test_add_token_to_uri(self):
        def assert_func(request):
            self.assertIn(self.token['access_token'], str(request.url))

        mock_response = MockDispatch({'a': 'a'}, assert_func=assert_func)
        with OAuth2Client(
                self.client_id,
                token=self.token,
                token_placement='uri',
                dispatch=mock_response
        ) as client:
            resp = client.get('https://i.b')

        data = resp.json()
        self.assertEqual(data['a'], 'a')

    def test_create_authorization_url(self):
        url = 'https://example.com/authorize?foo=bar'

        sess = OAuth2Client(client_id=self.client_id)
        auth_url, state = sess.create_authorization_url(url)
        self.assertIn(state, auth_url)
        self.assertIn(self.client_id, auth_url)
        self.assertIn('response_type=code', auth_url)

        sess = OAuth2Client(client_id=self.client_id, prompt='none')
        auth_url, state = sess.create_authorization_url(
            url, state='foo', redirect_uri='https://i.b', scope='profile')
        self.assertEqual(state, 'foo')
        self.assertIn('i.b', auth_url)
        self.assertIn('profile', auth_url)
        self.assertIn('prompt=none', auth_url)

    def test_code_challenge(self):
        sess = OAuth2Client(client_id=self.client_id, code_challenge_method='S256')

        url = 'https://example.com/authorize'
        auth_url, _ = sess.create_authorization_url(
            url, code_verifier=generate_token(48))
        self.assertIn('code_challenge', auth_url)
        self.assertIn('code_challenge_method=S256', auth_url)

    def test_token_from_fragment(self):
        sess = OAuth2Client(self.client_id)
        response_url = 'https://i.b/callback#' + url_encode(self.token.items())
        self.assertEqual(sess.token_from_fragment(response_url), self.token)
        token = sess.fetch_token(authorization_response=response_url)
        self.assertEqual(token, self.token)

    def test_fetch_token_post(self):
        url = 'https://example.com/token'

        def assert_func(request):
            body = request.content.decode()
            self.assertIn('code=v', body)
            self.assertIn('client_id=', body)
            self.assertIn('grant_type=authorization_code', body)

        mock_response = MockDispatch(self.token, assert_func=assert_func)
        with OAuth2Client(self.client_id, dispatch=mock_response) as client:
            token = client.fetch_token(url, authorization_response='https://i.b/?code=v')
            self.assertEqual(token, self.token)

        with OAuth2Client(
                self.client_id,
                token_endpoint_auth_method='none',
                dispatch=mock_response
        ) as client:
            token = client.fetch_token(url, code='v')
            self.assertEqual(token, self.token)

        mock_response = MockDispatch({'error': 'invalid_request'})
        with OAuth2Client(self.client_id, dispatch=mock_response) as client:
            self.assertRaises(OAuthError, client.fetch_token, url)

    def test_fetch_token_get(self):
        url = 'https://example.com/token'

        def assert_func(request):
            url = str(request.url)
            self.assertIn('code=v', url)
            self.assertIn('client_id=', url)
            self.assertIn('grant_type=authorization_code', url)

        mock_response = MockDispatch(self.token, assert_func=assert_func)
        with OAuth2Client(self.client_id, dispatch=mock_response) as client:
            authorization_response = 'https://i.b/?code=v'
            token = client.fetch_token(
                url, authorization_response=authorization_response, method='GET')
            self.assertEqual(token, self.token)

        with OAuth2Client(
                self.client_id,
                token_endpoint_auth_method='none',
                dispatch=mock_response
        ) as client:
            token = client.fetch_token(url, code='v', method='GET')
            self.assertEqual(token, self.token)

            token = client.fetch_token(url + '?q=a', code='v', method='GET')
            self.assertEqual(token, self.token)

    def test_token_auth_method_client_secret_post(self):
        url = 'https://example.com/token'

        def assert_func(request):
            body = request.content.decode()
            self.assertIn('code=v', body)
            self.assertIn('client_id=', body)
            self.assertIn('client_secret=bar', body)
            self.assertIn('grant_type=authorization_code', body)

        mock_response = MockDispatch(self.token, assert_func=assert_func)
        with OAuth2Client(
                self.client_id, 'bar',
                token_endpoint_auth_method='client_secret_post',
                dispatch=mock_response
        ) as client:
            token = client.fetch_token(url, code='v')

        self.assertEqual(token, self.token)

    def test_access_token_response_hook(self):
        url = 'https://example.com/token'

        def _access_token_response_hook(resp):
            self.assertEqual(resp.json(), self.token)
            return resp

        access_token_response_hook = mock.Mock(side_effect=_access_token_response_hook)
        dispatch = MockDispatch(self.token)
        with OAuth2Client(self.client_id, token=self.token, dispatch=dispatch) as sess:
            sess.register_compliance_hook(
                'access_token_response',
                access_token_response_hook
            )
            self.assertEqual(sess.fetch_token(url), self.token)
            self.assertTrue(access_token_response_hook.called)


    def test_password_grant_type(self):
        url = 'https://example.com/token'

        def assert_func(request):
            body = request.content.decode()
            self.assertIn('username=v', body)
            self.assertIn('scope=profile', body)
            self.assertIn('grant_type=password', body)

        dispatch = MockDispatch(self.token, assert_func=assert_func)
        with OAuth2Client(self.client_id, scope='profile', dispatch=dispatch) as sess:
            token = sess.fetch_token(url, username='v', password='v')
            self.assertEqual(token, self.token)

            token = sess.fetch_token(
                url, username='v', password='v', grant_type='password')
            self.assertEqual(token, self.token)

    def test_client_credentials_type(self):
        url = 'https://example.com/token'

        def assert_func(request):
            body = request.content.decode()
            self.assertIn('scope=profile', body)
            self.assertIn('grant_type=client_credentials', body)

        dispatch = MockDispatch(self.token, assert_func=assert_func)
        with OAuth2Client(self.client_id, scope='profile', dispatch=dispatch) as sess:
            token = sess.fetch_token(url)
            self.assertEqual(token, self.token)

            token = sess.fetch_token(url, grant_type='client_credentials')
            self.assertEqual(token, self.token)

    def test_cleans_previous_token_before_fetching_new_one(self):
        """Makes sure the previous token is cleaned before fetching a new one.
        The reason behind it is that, if the previous token is expired, this
        method shouldn't fail with a TokenExpiredError, since it's attempting
        to get a new one (which shouldn't be expired).
        """
        now = int(time.time())
        new_token = deepcopy(self.token)
        past = now - 7200
        self.token['expires_at'] = past
        new_token['expires_at'] = now + 3600
        url = 'https://example.com/token'

        dispatch = MockDispatch(new_token)
        with mock.patch('time.time', lambda: now):
            with OAuth2Client(self.client_id, token=self.token, dispatch=dispatch) as sess:
                self.assertEqual(sess.fetch_token(url), new_token)

    def test_token_status(self):
        token = dict(access_token='a', token_type='bearer', expires_at=100)
        sess = OAuth2Client('foo', token=token)

        self.assertTrue(sess.token.is_expired())

    def test_auto_refresh_token(self):

        def _update_token(token, refresh_token=None, access_token=None):
            self.assertEqual(refresh_token, 'b')
            self.assertEqual(token, self.token)

        update_token = mock.Mock(side_effect=_update_token)

        old_token = dict(
            access_token='a', refresh_token='b',
            token_type='bearer', expires_at=100
        )

        dispatch = MockDispatch(self.token)
        with OAuth2Client(
                'foo', token=old_token, token_endpoint='https://i.b/token',
                update_token=update_token, dispatch=dispatch
        ) as sess:
            sess.get('https://i.b/user')
            self.assertTrue(update_token.called)

        old_token = dict(
            access_token='a',
            token_type='bearer',
            expires_at=100
        )
        with OAuth2Client(
                'foo', token=old_token, token_endpoint='https://i.b/token',
                update_token=update_token, dispatch=dispatch
        ) as sess:
            self.assertRaises(OAuthError, sess.get, 'https://i.b/user')

    def test_auto_refresh_token2(self):

        def _update_token(token, refresh_token=None, access_token=None):
            self.assertEqual(access_token, 'a')
            self.assertEqual(token, self.token)

        update_token = mock.Mock(side_effect=_update_token)

        old_token = dict(
            access_token='a',
            token_type='bearer',
            expires_at=100
        )

        dispatch = MockDispatch(self.token)

        with OAuth2Client(
                'foo', token=old_token,
                token_endpoint='https://i.b/token',
                grant_type='client_credentials',
                dispatch=dispatch
        ) as sess:
            sess.get('https://i.b/user')
            self.assertFalse(update_token.called)

        with OAuth2Client(
                'foo', token=old_token, token_endpoint='https://i.b/token',
                update_token=update_token, grant_type='client_credentials',
                dispatch=dispatch
        ) as sess:
            sess.get('https://i.b/user')
            self.assertTrue(update_token.called)

    def test_revoke_token(self):
        answer = {'status': 'ok'}
        dispatch = MockDispatch(answer)

        def _revoke_token_request(url, headers, data):
            self.assertEqual(url, 'https://i.b/token')
            return url, headers, data

        revoke_token_request = mock.Mock(side_effect=_revoke_token_request)
        with OAuth2Client('a', dispatch=dispatch) as sess:
            resp = sess.revoke_token('https://i.b/token', 'hi')
            self.assertEqual(resp.json(), answer)

            resp = sess.revoke_token(
                'https://i.b/token', 'hi',
                token_type_hint='access_token'
            )
            self.assertEqual(resp.json(), answer)

            sess.register_compliance_hook(
                'revoke_token_request',
                revoke_token_request,
            )
            sess.revoke_token(
                'https://i.b/token', 'hi',
                body='',
                token_type_hint='access_token'
            )
            self.assertTrue(revoke_token_request.called)

    def test_request_without_token(self):
        with OAuth2Client('a') as client:
            self.assertRaises(OAuthError, client.get, 'https://i.b/token')
