import unittest

from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc8414 import get_well_known_url

WELL_KNOWN_URL = "/.well-known/oauth-authorization-server"


class WellKnownTest(unittest.TestCase):
    def test_no_suffix_issuer(self):
        self.assertEqual(get_well_known_url("https://authlib.org"), WELL_KNOWN_URL)
        self.assertEqual(get_well_known_url("https://authlib.org/"), WELL_KNOWN_URL)

    def test_with_suffix_issuer(self):
        self.assertEqual(
            get_well_known_url("https://authlib.org/issuer1"),
            WELL_KNOWN_URL + "/issuer1",
        )
        self.assertEqual(
            get_well_known_url("https://authlib.org/a/b/c"), WELL_KNOWN_URL + "/a/b/c"
        )

    def test_with_external(self):
        self.assertEqual(
            get_well_known_url("https://authlib.org", external=True),
            "https://authlib.org" + WELL_KNOWN_URL,
        )

    def test_with_changed_suffix(self):
        url = get_well_known_url("https://authlib.org", suffix="openid-configuration")
        self.assertEqual(url, "/.well-known/openid-configuration")
        url = get_well_known_url(
            "https://authlib.org", external=True, suffix="openid-configuration"
        )
        self.assertEqual(url, "https://authlib.org/.well-known/openid-configuration")


class AuthorizationServerMetadataTest(unittest.TestCase):
    def test_validate_issuer(self):
        #: missing
        metadata = AuthorizationServerMetadata({})
        with self.assertRaises(ValueError) as cm:
            metadata.validate()
        self.assertEqual('"issuer" is required', str(cm.exception))

        #: https
        metadata = AuthorizationServerMetadata({"issuer": "http://authlib.org/"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn("https", str(cm.exception))

        #: query
        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/?a=b"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn("query", str(cm.exception))

        #: fragment
        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/#a=b"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_issuer()
        self.assertIn("fragment", str(cm.exception))

        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/"})
        metadata.validate_issuer()

    def test_validate_authorization_endpoint(self):
        # https
        metadata = AuthorizationServerMetadata(
            {"authorization_endpoint": "http://authlib.org/"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_authorization_endpoint()
        self.assertIn("https", str(cm.exception))

        # valid https
        metadata = AuthorizationServerMetadata(
            {"authorization_endpoint": "https://authlib.org/"}
        )
        metadata.validate_authorization_endpoint()

        # missing
        metadata = AuthorizationServerMetadata()
        with self.assertRaises(ValueError) as cm:
            metadata.validate_authorization_endpoint()
        self.assertIn("required", str(cm.exception))

        # valid missing
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
        metadata.validate_authorization_endpoint()

    def test_validate_token_endpoint(self):
        # implicit
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["implicit"]})
        metadata.validate_token_endpoint()

        # missing
        metadata = AuthorizationServerMetadata()
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint()
        self.assertIn("required", str(cm.exception))

        # https
        metadata = AuthorizationServerMetadata(
            {"token_endpoint": "http://authlib.org/"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint()
        self.assertIn("https", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"token_endpoint": "https://authlib.org/"}
        )
        metadata.validate_token_endpoint()

    def test_validate_jwks_uri(self):
        # can missing
        metadata = AuthorizationServerMetadata()
        metadata.validate_jwks_uri()

        metadata = AuthorizationServerMetadata(
            {"jwks_uri": "http://authlib.org/jwks.json"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_jwks_uri()
        self.assertIn("https", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"jwks_uri": "https://authlib.org/jwks.json"}
        )
        metadata.validate_jwks_uri()

    def test_validate_registration_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_registration_endpoint()

        metadata = AuthorizationServerMetadata(
            {"registration_endpoint": "http://authlib.org/"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_registration_endpoint()
        self.assertIn("https", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"registration_endpoint": "https://authlib.org/"}
        )
        metadata.validate_registration_endpoint()

    def test_validate_scopes_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_scopes_supported()

        # not array
        metadata = AuthorizationServerMetadata({"scopes_supported": "foo"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_scopes_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata({"scopes_supported": ["foo"]})
        metadata.validate_scopes_supported()

    def test_validate_response_types_supported(self):
        # missing
        metadata = AuthorizationServerMetadata()
        with self.assertRaises(ValueError) as cm:
            metadata.validate_response_types_supported()
        self.assertIn("required", str(cm.exception))

        # not array
        metadata = AuthorizationServerMetadata({"response_types_supported": "code"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_response_types_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata({"response_types_supported": ["code"]})
        metadata.validate_response_types_supported()

    def test_validate_response_modes_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_response_modes_supported()

        # not array
        metadata = AuthorizationServerMetadata({"response_modes_supported": "query"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_response_modes_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata({"response_modes_supported": ["query"]})
        metadata.validate_response_modes_supported()

    def test_validate_grant_types_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_grant_types_supported()

        # not array
        metadata = AuthorizationServerMetadata({"grant_types_supported": "password"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_grant_types_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
        metadata.validate_grant_types_supported()

    def test_validate_token_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_token_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint_auth_methods_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_token_endpoint_auth_methods_supported()

    def test_validate_token_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_token_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()
        self.assertIn("required", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()
        self.assertIn("JSON array", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {
                "token_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["RS256", "none"],
            }
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()
        self.assertIn("none", str(cm.exception))

    def test_validate_service_documentation(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_service_documentation()

        metadata = AuthorizationServerMetadata({"service_documentation": "invalid"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_service_documentation()
        self.assertIn("MUST be a URL", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"service_documentation": "https://authlib.org/"}
        )
        metadata.validate_service_documentation()

    def test_validate_ui_locales_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_ui_locales_supported()

        # not array
        metadata = AuthorizationServerMetadata({"ui_locales_supported": "en"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_ui_locales_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata({"ui_locales_supported": ["en"]})
        metadata.validate_ui_locales_supported()

    def test_validate_op_policy_uri(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_op_policy_uri()

        metadata = AuthorizationServerMetadata({"op_policy_uri": "invalid"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_op_policy_uri()
        self.assertIn("MUST be a URL", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"op_policy_uri": "https://authlib.org/"}
        )
        metadata.validate_op_policy_uri()

    def test_validate_op_tos_uri(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_op_tos_uri()

        metadata = AuthorizationServerMetadata({"op_tos_uri": "invalid"})
        with self.assertRaises(ValueError) as cm:
            metadata.validate_op_tos_uri()
        self.assertIn("MUST be a URL", str(cm.exception))

        metadata = AuthorizationServerMetadata({"op_tos_uri": "https://authlib.org/"})
        metadata.validate_op_tos_uri()

    def test_validate_revocation_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint()

        # https
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint": "http://authlib.org/"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_revocation_endpoint()
        self.assertIn("https", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint": "https://authlib.org/"}
        )
        metadata.validate_revocation_endpoint()

    def test_validate_revocation_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_revocation_endpoint_auth_methods_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_revocation_endpoint_auth_methods_supported()

    def test_validate_revocation_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()
        self.assertIn("required", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()
        self.assertIn("JSON array", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {
                "revocation_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "revocation_endpoint_auth_signing_alg_values_supported": [
                    "RS256",
                    "none",
                ],
            }
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()
        self.assertIn("none", str(cm.exception))

    def test_validate_introspection_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint()

        # https
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint": "http://authlib.org/"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_introspection_endpoint()
        self.assertIn("https", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint": "https://authlib.org/"}
        )
        metadata.validate_introspection_endpoint()

    def test_validate_introspection_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_introspection_endpoint_auth_methods_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_introspection_endpoint_auth_methods_supported()

    def test_validate_introspection_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()
        self.assertIn("required", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()
        self.assertIn("JSON array", str(cm.exception))

        metadata = AuthorizationServerMetadata(
            {
                "introspection_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "introspection_endpoint_auth_signing_alg_values_supported": [
                    "RS256",
                    "none",
                ],
            }
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()
        self.assertIn("none", str(cm.exception))

    def test_validate_code_challenge_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_code_challenge_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"code_challenge_methods_supported": "S256"}
        )
        with self.assertRaises(ValueError) as cm:
            metadata.validate_code_challenge_methods_supported()
        self.assertIn("JSON array", str(cm.exception))

        # valid
        metadata = AuthorizationServerMetadata(
            {"code_challenge_methods_supported": ["S256"]}
        )
        metadata.validate_code_challenge_methods_supported()
