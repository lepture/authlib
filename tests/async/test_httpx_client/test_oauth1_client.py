from unittest import TestCase
from authlib.integrations.httpx_client import (
    OAuthError,
    OAuth1Client,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_QUERY,
)
from .utils import MockDispatch


class OAuth1ClientTest(TestCase):
    oauth_url = 'https://example.com/oauth'

    def test_fetch_request_token_via_header(self):
        request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

        def assert_func(request):
            auth_header = request.headers.get('authorization')
            self.assertIn('oauth_consumer_key="id"', auth_header)
            self.assertIn('oauth_signature=', auth_header)

        mock_response = MockDispatch(request_token, assert_func=assert_func)
        with OAuth1Client('id', 'secret', dispatch=mock_response) as client:
            response = client.fetch_request_token(self.oauth_url)

        self.assertEqual(response, request_token)

    def test_fetch_request_token_via_body(self):
        request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

        def assert_func(request):
            auth_header = request.headers.get('authorization')
            self.assertIsNone(auth_header)

            self.assertIn(b'oauth_consumer_key=id', request.content)
            self.assertIn(b'&oauth_signature=', request.content)

        mock_response = MockDispatch(request_token, assert_func=assert_func)

        with OAuth1Client(
            'id', 'secret', signature_type=SIGNATURE_TYPE_BODY,
            dispatch=mock_response,
        ) as client:
            response = client.fetch_request_token(self.oauth_url)

        self.assertEqual(response, request_token)

    def test_fetch_request_token_via_query(self):
        request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

        def assert_func(request):
            auth_header = request.headers.get('authorization')
            self.assertIsNone(auth_header)

            url = str(request.url)
            self.assertIn('oauth_consumer_key=id', url)
            self.assertIn('&oauth_signature=', url)

        mock_response = MockDispatch(request_token, assert_func=assert_func)

        with OAuth1Client(
            'id', 'secret', signature_type=SIGNATURE_TYPE_QUERY,
            dispatch=mock_response,
        ) as client:
            response = client.fetch_request_token(self.oauth_url)

        self.assertEqual(response, request_token)

    def test_fetch_access_token(self):
        request_token = {'oauth_token': '1', 'oauth_token_secret': '2'}

        def assert_func(request):
            auth_header = request.headers.get('authorization')
            self.assertIn('oauth_verifier="d"', auth_header)
            self.assertIn('oauth_token="foo"', auth_header)
            self.assertIn('oauth_consumer_key="id"', auth_header)
            self.assertIn('oauth_signature=', auth_header)

        mock_response = MockDispatch(request_token, assert_func=assert_func)
        with OAuth1Client(
            'id', 'secret', token='foo', token_secret='bar',
            dispatch=mock_response,
        ) as client:
            self.assertRaises(
                OAuthError,
                client.fetch_access_token, self.oauth_url
            )
            response = client.fetch_access_token(self.oauth_url, verifier='d')

        self.assertEqual(response, request_token)

    def test_get_via_header(self):
        mock_response = MockDispatch(b'hello')
        with OAuth1Client(
            'id', 'secret', token='foo', token_secret='bar',
            dispatch=mock_response,
        ) as client:
            response = client.get('https://example.com/')

        self.assertEqual(b'hello', response.content)
        request = response.request
        auth_header = request.headers.get('authorization')
        self.assertIn('oauth_token="foo"', auth_header)
        self.assertIn('oauth_consumer_key="id"', auth_header)
        self.assertIn('oauth_signature=', auth_header)

    def test_get_via_body(self):
        mock_response = MockDispatch(b'hello')
        with OAuth1Client(
            'id', 'secret', token='foo', token_secret='bar',
            signature_type=SIGNATURE_TYPE_BODY,
            dispatch=mock_response,
        ) as client:
            response = client.post('https://example.com/')

        self.assertEqual(b'hello', response.content)
        request = response.request
        auth_header = request.headers.get('authorization')
        self.assertIsNone(auth_header)

        self.assertIn(b'oauth_token=foo', request.content)
        self.assertIn(b'oauth_consumer_key=id', request.content)
        self.assertIn(b'oauth_signature=', request.content)

    def test_get_via_query(self):
        mock_response = MockDispatch(b'hello')
        with OAuth1Client(
            'id', 'secret', token='foo', token_secret='bar',
            signature_type=SIGNATURE_TYPE_QUERY,
            dispatch=mock_response,
        ) as client:
            response = client.get('https://example.com/')

        self.assertEqual(b'hello', response.content)
        request = response.request
        auth_header = request.headers.get('authorization')
        self.assertIsNone(auth_header)

        url = str(request.url)
        self.assertIn('oauth_token=foo', url)
        self.assertIn('oauth_consumer_key=id', url)
        self.assertIn('oauth_signature=', url)
