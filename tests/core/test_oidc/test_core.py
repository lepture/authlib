import unittest

from authlib.jose.errors import InvalidClaimError
from authlib.jose.errors import MissingClaimError
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo
from authlib.oidc.core import get_claim_cls_by_response_type


class IDTokenTest(unittest.TestCase):
    def test_essential_claims(self):
        claims = CodeIDToken({}, {})
        self.assertRaises(MissingClaimError, claims.validate)
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
        )
        claims.validate(1000)

    def test_validate_auth_time(self):
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
        )
        claims.params = {"max_age": 100}
        self.assertRaises(MissingClaimError, claims.validate, 1000)

        claims["auth_time"] = "foo"
        self.assertRaises(InvalidClaimError, claims.validate, 1000)

    def test_validate_nonce(self):
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
        )
        claims.params = {"nonce": "foo"}
        self.assertRaises(MissingClaimError, claims.validate, 1000)
        claims["nonce"] = "bar"
        self.assertRaises(InvalidClaimError, claims.validate, 1000)
        claims["nonce"] = "foo"
        claims.validate(1000)

    def test_validate_amr(self):
        claims = CodeIDToken(
            {
                "iss": "1",
                "sub": "1",
                "aud": "1",
                "exp": 10000,
                "iat": 100,
                "amr": "invalid",
            },
            {},
        )
        self.assertRaises(InvalidClaimError, claims.validate, 1000)

    def test_validate_azp(self):
        claims = CodeIDToken(
            {
                "iss": "1",
                "sub": "1",
                "aud": "1",
                "exp": 10000,
                "iat": 100,
            },
            {},
        )
        claims.params = {"client_id": "2"}
        self.assertRaises(MissingClaimError, claims.validate, 1000)

        claims["azp"] = "1"
        self.assertRaises(InvalidClaimError, claims.validate, 1000)

        claims["azp"] = "2"
        claims.validate(1000)

    def test_validate_at_hash(self):
        claims = CodeIDToken(
            {
                "iss": "1",
                "sub": "1",
                "aud": "1",
                "exp": 10000,
                "iat": 100,
                "at_hash": "a",
            },
            {},
        )
        claims.params = {"access_token": "a"}

        # invalid alg won't raise
        claims.header = {"alg": "HS222"}
        claims.validate(1000)

        claims.header = {"alg": "HS256"}
        self.assertRaises(InvalidClaimError, claims.validate, 1000)

    def test_implicit_id_token(self):
        claims = ImplicitIDToken(
            {
                "iss": "1",
                "sub": "1",
                "aud": "1",
                "exp": 10000,
                "iat": 100,
                "nonce": "a",
            },
            {},
        )
        claims.params = {"access_token": "a"}
        self.assertRaises(MissingClaimError, claims.validate, 1000)

    def test_hybrid_id_token(self):
        claims = HybridIDToken(
            {
                "iss": "1",
                "sub": "1",
                "aud": "1",
                "exp": 10000,
                "iat": 100,
                "nonce": "a",
            },
            {},
        )
        claims.validate(1000)

        claims.params = {"code": "a"}
        self.assertRaises(MissingClaimError, claims.validate, 1000)

        # invalid alg won't raise
        claims.header = {"alg": "HS222"}
        claims["c_hash"] = "a"
        claims.validate(1000)

        claims.header = {"alg": "HS256"}
        self.assertRaises(InvalidClaimError, claims.validate, 1000)

    def test_get_claim_cls_by_response_type(self):
        cls = get_claim_cls_by_response_type("id_token")
        self.assertEqual(cls, ImplicitIDToken)
        cls = get_claim_cls_by_response_type("code")
        self.assertEqual(cls, CodeIDToken)
        cls = get_claim_cls_by_response_type("code id_token")
        self.assertEqual(cls, HybridIDToken)
        cls = get_claim_cls_by_response_type("none")
        self.assertIsNone(cls)


class UserInfoTest(unittest.TestCase):
    def test_getattribute(self):
        user = UserInfo({"sub": "1"})
        self.assertEqual(user.sub, "1")
        self.assertIsNone(user.email, None)
        self.assertRaises(AttributeError, lambda: user.invalid)
