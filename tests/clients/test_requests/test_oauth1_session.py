from io import StringIO
from unittest import TestCase
from unittest import mock

import requests

from authlib.common.encoding import to_unicode
from authlib.integrations.requests_client import OAuth1Session
from authlib.integrations.requests_client import OAuthError
from authlib.oauth1 import SIGNATURE_PLAINTEXT
from authlib.oauth1 import SIGNATURE_RSA_SHA1
from authlib.oauth1 import SIGNATURE_TYPE_BODY
from authlib.oauth1 import SIGNATURE_TYPE_QUERY
from authlib.oauth1.rfc5849.util import escape

from ..util import mock_text_response
from ..util import read_key_file

TEST_RSA_OAUTH_SIGNATURE = (
    "j8WF8PGjojT82aUDd2EL%2Bz7HCoHInFzWUpiEKMCy%2BJ2cYHWcBS7mXlmFDLgAKV0"
    "P%2FyX4TrpXODYnJ6dRWdfghqwDpi%2FlQmB2jxCiGMdJoYxh3c5zDf26gEbGdP6D7O"
    "Ssp5HUnzH6sNkmVjuE%2FxoJcHJdc23H6GhOs7VJ2LWNdbhKWP%2FMMlTrcoQDn8lz"
    "%2Fb24WsJ6ae1txkUzpFOOlLM8aTdNtGL4OtsubOlRhNqnAFq93FyhXg0KjzUyIZzmMX"
    "9Vx90jTks5QeBGYcLE0Op2iHb2u%2FO%2BEgdwFchgEwE5LgMUyHUI4F3Wglp28yHOAM"
    "jPkI%2FkWMvpxtMrU3Z3KN31WQ%3D%3D"
)


class OAuth1SessionTest(TestCase):
    def test_no_client_id(self):
        self.assertRaises(ValueError, lambda: OAuth1Session(None))

    def test_signature_types(self):
        def verify_signature(getter):
            def fake_send(r, **kwargs):
                signature = to_unicode(getter(r))
                self.assertIn("oauth_signature", signature)
                resp = mock.MagicMock(spec=requests.Response)
                resp.cookies = []
                return resp

            return fake_send

        header = OAuth1Session("foo")
        header.send = verify_signature(lambda r: r.headers["Authorization"])
        header.post("https://i.b")

        query = OAuth1Session("foo", signature_type=SIGNATURE_TYPE_QUERY)
        query.send = verify_signature(lambda r: r.url)
        query.post("https://i.b")

        body = OAuth1Session("foo", signature_type=SIGNATURE_TYPE_BODY)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body.send = verify_signature(lambda r: r.body)
        body.post("https://i.b", headers=headers, data="")

    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_timestamp")
    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_nonce")
    def test_signature_methods(self, generate_nonce, generate_timestamp):
        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"

        signature = ", ".join(
            [
                'OAuth oauth_nonce="abc"',
                'oauth_timestamp="123"',
                'oauth_version="1.0"',
                'oauth_signature_method="HMAC-SHA1"',
                'oauth_consumer_key="foo"',
                'oauth_signature="h2sRqLArjhlc5p3FTkuNogVHlKE%3D"',
            ]
        )
        auth = OAuth1Session("foo")
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

        signature = (
            "OAuth "
            'oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="PLAINTEXT", oauth_consumer_key="foo", '
            'oauth_signature="%26"'
        )
        auth = OAuth1Session("foo", signature_method=SIGNATURE_PLAINTEXT)
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

        signature = (
            "OAuth "
            'oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="RSA-SHA1", oauth_consumer_key="foo", '
            f'oauth_signature="{TEST_RSA_OAUTH_SIGNATURE}"'
        )

        rsa_key = read_key_file("rsa_private.pem")
        auth = OAuth1Session(
            "foo", signature_method=SIGNATURE_RSA_SHA1, rsa_key=rsa_key
        )
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_timestamp")
    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_nonce")
    def test_binary_upload(self, generate_nonce, generate_timestamp):
        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"
        fake_xml = StringIO("hello world")
        headers = {"Content-Type": "application/xml"}

        def fake_send(r, **kwargs):
            auth_header = r.headers["Authorization"]
            self.assertIn("oauth_body_hash", auth_header)

        auth = OAuth1Session("foo", force_include_body=True)
        auth.send = fake_send
        auth.post("https://i.b", headers=headers, files=[("fake", fake_xml)])

    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_timestamp")
    @mock.patch("authlib.oauth1.rfc5849.client_auth.generate_nonce")
    def test_nonascii(self, generate_nonce, generate_timestamp):
        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"
        signature = (
            'OAuth oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="HMAC-SHA1", oauth_consumer_key="foo", '
            'oauth_signature="W0haoue5IZAZoaJiYCtfqwMf8x8%3D"'
        )
        auth = OAuth1Session("foo")
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b?cjk=%E5%95%A6%E5%95%A6")

    def test_redirect_uri(self):
        sess = OAuth1Session("foo")
        self.assertIsNone(sess.redirect_uri)
        url = "https://i.b"
        sess.redirect_uri = url
        self.assertEqual(sess.redirect_uri, url)

    def test_set_token(self):
        sess = OAuth1Session("foo")
        try:
            sess.token = {}
        except OAuthError as exc:
            self.assertEqual(exc.error, "missing_token")

        sess.token = {"oauth_token": "a", "oauth_token_secret": "b"}
        self.assertIsNone(sess.token["oauth_verifier"])
        sess.token = {"oauth_token": "a", "oauth_verifier": "c"}
        self.assertEqual(sess.token["oauth_token_secret"], "b")
        self.assertEqual(sess.token["oauth_verifier"], "c")

        sess.token = None
        self.assertIsNone(sess.token["oauth_token"])
        self.assertIsNone(sess.token["oauth_token_secret"])
        self.assertIsNone(sess.token["oauth_verifier"])

    def test_create_authorization_url(self):
        auth = OAuth1Session("foo")
        url = "https://example.comm/authorize"
        token = "asluif023sf"
        auth_url = auth.create_authorization_url(url, request_token=token)
        self.assertEqual(auth_url, url + "?oauth_token=" + token)
        redirect_uri = "https://c.b"
        auth = OAuth1Session("foo", redirect_uri=redirect_uri)
        auth_url = auth.create_authorization_url(url, request_token=token)
        self.assertIn(escape(redirect_uri), auth_url)

    def test_parse_response_url(self):
        url = "https://i.b/callback?oauth_token=foo&oauth_verifier=bar"
        auth = OAuth1Session("foo")
        resp = auth.parse_authorization_response(url)
        self.assertEqual(resp["oauth_token"], "foo")
        self.assertEqual(resp["oauth_verifier"], "bar")
        for k, v in resp.items():
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

    def test_fetch_request_token(self):
        auth = OAuth1Session("foo", realm="A")
        auth.send = mock_text_response("oauth_token=foo")
        resp = auth.fetch_request_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

        resp = auth.fetch_request_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")

    def test_fetch_request_token_with_optional_arguments(self):
        auth = OAuth1Session("foo")
        auth.send = mock_text_response("oauth_token=foo")
        resp = auth.fetch_request_token(
            "https://example.com/token", verify=False, stream=True
        )
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

    def test_fetch_access_token(self):
        auth = OAuth1Session("foo", verifier="bar")
        auth.send = mock_text_response("oauth_token=foo")
        resp = auth.fetch_access_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

        auth = OAuth1Session("foo", verifier="bar")
        auth.send = mock_text_response('{"oauth_token":"foo"}')
        resp = auth.fetch_access_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")

        auth = OAuth1Session("foo")
        auth.send = mock_text_response("oauth_token=foo")
        resp = auth.fetch_access_token("https://example.com/token", verifier="bar")
        self.assertEqual(resp["oauth_token"], "foo")

    def test_fetch_access_token_with_optional_arguments(self):
        auth = OAuth1Session("foo", verifier="bar")
        auth.send = mock_text_response("oauth_token=foo")
        resp = auth.fetch_access_token(
            "https://example.com/token", verify=False, stream=True
        )
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertTrue(isinstance(k, str))
            self.assertTrue(isinstance(v, str))

    def _test_fetch_access_token_raises_error(self, session):
        """Assert that an error is being raised whenever there's no verifier
        passed in to the client.
        """
        session.send = mock_text_response("oauth_token=foo")

        # Use a try-except block so that we can assert on the exception message
        # being raised and also keep the Python2.6 compatibility where
        # assertRaises is not a context manager.
        try:
            session.fetch_access_token("https://example.com/token")
        except OAuthError as exc:
            self.assertEqual(exc.error, "missing_verifier")

    def test_fetch_token_invalid_response(self):
        auth = OAuth1Session("foo")
        auth.send = mock_text_response("not valid urlencoded response!")
        self.assertRaises(
            ValueError, auth.fetch_request_token, "https://example.com/token"
        )

        for code in (400, 401, 403):
            auth.send = mock_text_response("valid=response", code)
            # use try/catch rather than self.assertRaises, so we can
            # assert on the properties of the exception
            try:
                auth.fetch_request_token("https://example.com/token")
            except OAuthError as err:
                self.assertEqual(err.error, "fetch_token_denied")
            else:  # no exception raised
                self.fail("ValueError not raised")

    def test_fetch_access_token_missing_verifier(self):
        self._test_fetch_access_token_raises_error(OAuth1Session("foo"))

    def test_fetch_access_token_has_verifier_is_none(self):
        session = OAuth1Session("foo")
        session.auth.verifier = None
        self._test_fetch_access_token_raises_error(session)

    def verify_signature(self, signature):
        def fake_send(r, **kwargs):
            auth_header = to_unicode(r.headers["Authorization"])
            self.assertEqual(auth_header, signature)
            resp = mock.MagicMock(spec=requests.Response)
            resp.cookies = []
            return resp

        return fake_send
