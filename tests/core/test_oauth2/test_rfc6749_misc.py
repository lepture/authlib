import base64
import unittest

from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util


class OAuth2ParametersTest(unittest.TestCase):
    def test_parse_authorization_code_response(self):
        self.assertRaises(
            errors.MissingCodeException,
            parameters.parse_authorization_code_response,
            "https://i.b/?state=c",
        )

        self.assertRaises(
            errors.MismatchingStateException,
            parameters.parse_authorization_code_response,
            "https://i.b/?code=a&state=c",
            "b",
        )

        url = "https://i.b/?code=a&state=c"
        rv = parameters.parse_authorization_code_response(url, "c")
        self.assertEqual(rv, {"code": "a", "state": "c"})

    def test_parse_implicit_response(self):
        self.assertRaises(
            errors.MissingTokenException,
            parameters.parse_implicit_response,
            "https://i.b/#a=b",
        )

        self.assertRaises(
            errors.MissingTokenTypeException,
            parameters.parse_implicit_response,
            "https://i.b/#access_token=a",
        )

        self.assertRaises(
            errors.MismatchingStateException,
            parameters.parse_implicit_response,
            "https://i.b/#access_token=a&token_type=bearer&state=c",
            "abc",
        )

        url = "https://i.b/#access_token=a&token_type=bearer&state=c"
        rv = parameters.parse_implicit_response(url, "c")
        self.assertEqual(
            rv, {"access_token": "a", "token_type": "bearer", "state": "c"}
        )

    def test_prepare_grant_uri(self):
        grant_uri = parameters.prepare_grant_uri(
            "https://i.b/authorize", "dev", "code", max_age=0
        )
        self.assertEqual(
            grant_uri,
            "https://i.b/authorize?response_type=code&client_id=dev&max_age=0",
        )


class OAuth2UtilTest(unittest.TestCase):
    def test_list_to_scope(self):
        self.assertEqual(util.list_to_scope(["a", "b"]), "a b")
        self.assertEqual(util.list_to_scope("a b"), "a b")
        self.assertIsNone(util.list_to_scope(None))

    def test_scope_to_list(self):
        self.assertEqual(util.scope_to_list("a b"), ["a", "b"])
        self.assertEqual(util.scope_to_list(["a", "b"]), ["a", "b"])
        self.assertIsNone(util.scope_to_list(None))

    def test_extract_basic_authorization(self):
        self.assertEqual(util.extract_basic_authorization({}), (None, None))
        self.assertEqual(
            util.extract_basic_authorization({"Authorization": "invalid"}), (None, None)
        )

        text = "Basic invalid-base64"
        self.assertEqual(
            util.extract_basic_authorization({"Authorization": text}), (None, None)
        )

        text = "Basic {}".format(base64.b64encode(b"a").decode())
        self.assertEqual(
            util.extract_basic_authorization({"Authorization": text}), ("a", None)
        )

        text = "Basic {}".format(base64.b64encode(b"a:b").decode())
        self.assertEqual(
            util.extract_basic_authorization({"Authorization": text}), ("a", "b")
        )
