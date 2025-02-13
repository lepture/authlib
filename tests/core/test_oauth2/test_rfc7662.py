import unittest

from authlib.oauth2.rfc7662 import IntrospectionToken


class IntrospectionTokenTest(unittest.TestCase):
    def test_client_id(self):
        token = IntrospectionToken()
        self.assertIsNone(token.client_id)
        self.assertIsNone(token.get_client_id())

        token = IntrospectionToken({"client_id": "foo"})
        self.assertEqual(token.client_id, "foo")
        self.assertEqual(token.get_client_id(), "foo")

    def test_scope(self):
        token = IntrospectionToken()
        self.assertIsNone(token.scope)
        self.assertIsNone(token.get_scope())

        token = IntrospectionToken({"scope": "foo"})
        self.assertEqual(token.scope, "foo")
        self.assertEqual(token.get_scope(), "foo")

    def test_expires_in(self):
        token = IntrospectionToken()
        self.assertEqual(token.get_expires_in(), 0)

    def test_expires_at(self):
        token = IntrospectionToken()
        self.assertIsNone(token.exp)
        self.assertEqual(token.get_expires_at(), 0)

        token = IntrospectionToken({"exp": 3600})
        self.assertEqual(token.exp, 3600)
        self.assertEqual(token.get_expires_at(), 3600)

    def test_all_attributes(self):
        # https://tools.ietf.org/html/rfc7662#section-2.2
        token = IntrospectionToken()
        self.assertIsNone(token.active)
        self.assertIsNone(token.scope)
        self.assertIsNone(token.client_id)
        self.assertIsNone(token.username)
        self.assertIsNone(token.token_type)
        self.assertIsNone(token.exp)
        self.assertIsNone(token.iat)
        self.assertIsNone(token.nbf)
        self.assertIsNone(token.sub)
        self.assertIsNone(token.aud)
        self.assertIsNone(token.iss)
        self.assertIsNone(token.jti)

    def test_invalid_attr(self):
        token = IntrospectionToken()
        self.assertRaises(AttributeError, lambda: token.invalid)
