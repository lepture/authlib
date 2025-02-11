from unittest import TestCase

from authlib.jose.errors import InvalidClaimError
from authlib.oauth2.rfc7591 import ClientMetadataClaims


class ClientMetadataClaimsTest(TestCase):
    def test_validate_redirect_uris(self):
        claims = ClientMetadataClaims({"redirect_uris": ["foo"]}, {})
        self.assertRaises(InvalidClaimError, claims.validate)

    def test_validate_client_uri(self):
        claims = ClientMetadataClaims({"client_uri": "foo"}, {})
        self.assertRaises(InvalidClaimError, claims.validate)

    def test_validate_logo_uri(self):
        claims = ClientMetadataClaims({"logo_uri": "foo"}, {})
        self.assertRaises(InvalidClaimError, claims.validate)

    def test_validate_tos_uri(self):
        claims = ClientMetadataClaims({"tos_uri": "foo"}, {})
        self.assertRaises(InvalidClaimError, claims.validate)

    def test_validate_policy_uri(self):
        claims = ClientMetadataClaims({"policy_uri": "foo"}, {})
        self.assertRaises(InvalidClaimError, claims.validate)

    def test_validate_jwks_uri(self):
        claims = ClientMetadataClaims({"jwks_uri": "foo"}, {})
        self.assertRaises(InvalidClaimError, claims.validate)
