import json
import unittest

from authlib.jose import JsonWebSignature
from authlib.jose import errors
from tests.util import read_file_path


class JWSTest(unittest.TestCase):
    def test_invalid_input(self):
        jws = JsonWebSignature()
        self.assertRaises(errors.DecodeError, jws.deserialize, "a", "k")
        self.assertRaises(errors.DecodeError, jws.deserialize, "a.b.c", "k")
        self.assertRaises(errors.DecodeError, jws.deserialize, "YQ.YQ.YQ", "k")  # a
        self.assertRaises(errors.DecodeError, jws.deserialize, "W10.a.YQ", "k")  # []
        self.assertRaises(errors.DecodeError, jws.deserialize, "e30.a.YQ", "k")  # {}
        self.assertRaises(
            errors.DecodeError, jws.deserialize, "eyJhbGciOiJzIn0.a.YQ", "k"
        )
        self.assertRaises(
            errors.DecodeError, jws.deserialize, "eyJhbGciOiJzIn0.YQ.a", "k"
        )

    def test_invalid_alg(self):
        jws = JsonWebSignature()
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.deserialize,
            "eyJhbGciOiJzIn0.YQ.YQ",
            "k",
        )
        self.assertRaises(errors.MissingAlgorithmError, jws.serialize, {}, "", "k")
        self.assertRaises(
            errors.UnsupportedAlgorithmError, jws.serialize, {"alg": "s"}, "", "k"
        )

    def test_bad_signature(self):
        jws = JsonWebSignature()
        s = "eyJhbGciOiJIUzI1NiJ9.YQ.YQ"
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, "k")

    def test_not_supported_alg(self):
        jws = JsonWebSignature(algorithms=["HS256"])
        s = jws.serialize({"alg": "HS256"}, "hello", "secret")

        jws = JsonWebSignature(algorithms=["RS256"])
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            lambda: jws.serialize({"alg": "HS256"}, "hello", "secret"),
        )

        self.assertRaises(
            errors.UnsupportedAlgorithmError, jws.deserialize, s, "secret"
        )

    def test_compact_jws(self):
        jws = JsonWebSignature(algorithms=["HS256"])
        s = jws.serialize({"alg": "HS256"}, "hello", "secret")
        data = jws.deserialize(s, "secret")
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "HS256")
        self.assertNotIn("signature", data)

    def test_compact_rsa(self):
        jws = JsonWebSignature()
        private_key = read_file_path("rsa_private.pem")
        public_key = read_file_path("rsa_public.pem")
        s = jws.serialize({"alg": "RS256"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "RS256")

        # can deserialize with private key
        data2 = jws.deserialize(s, private_key)
        self.assertEqual(data, data2)

        ssh_pub_key = read_file_path("ssh_public.pem")
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, ssh_pub_key)

    def test_compact_rsa_pss(self):
        jws = JsonWebSignature()
        private_key = read_file_path("rsa_private.pem")
        public_key = read_file_path("rsa_public.pem")
        s = jws.serialize({"alg": "PS256"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "PS256")
        ssh_pub_key = read_file_path("ssh_public.pem")
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, ssh_pub_key)

    def test_compact_none(self):
        jws = JsonWebSignature()
        s = jws.serialize({"alg": "none"}, "hello", "")
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, "")

    def test_flattened_json_jws(self):
        jws = JsonWebSignature()
        protected = {"alg": "HS256"}
        header = {"protected": protected, "header": {"kid": "a"}}
        s = jws.serialize(header, "hello", "secret")
        self.assertIsInstance(s, dict)

        data = jws.deserialize(s, "secret")
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "HS256")
        self.assertNotIn("protected", data)

    def test_nested_json_jws(self):
        jws = JsonWebSignature()
        protected = {"alg": "HS256"}
        header = {"protected": protected, "header": {"kid": "a"}}
        s = jws.serialize([header], "hello", "secret")
        self.assertIsInstance(s, dict)
        self.assertIn("signatures", s)

        data = jws.deserialize(s, "secret")
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header[0]["alg"], "HS256")
        self.assertNotIn("signatures", data)

        # test bad signature
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, "f")

    def test_function_key(self):
        protected = {"alg": "HS256"}
        header = [
            {"protected": protected, "header": {"kid": "a"}},
            {"protected": protected, "header": {"kid": "b"}},
        ]

        def load_key(header, payload):
            self.assertEqual(payload, b"hello")
            kid = header.get("kid")
            if kid == "a":
                return "secret-a"
            return "secret-b"

        jws = JsonWebSignature()
        s = jws.serialize(header, b"hello", load_key)
        self.assertIsInstance(s, dict)
        self.assertIn("signatures", s)

        data = jws.deserialize(json.dumps(s), load_key)
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header[0]["alg"], "HS256")
        self.assertNotIn("signature", data)

    def test_serialize_json_empty_payload(self):
        jws = JsonWebSignature()
        protected = {"alg": "HS256"}
        header = {"protected": protected, "header": {"kid": "a"}}
        s = jws.serialize_json(header, b"", "secret")
        data = jws.deserialize_json(s, "secret")
        self.assertEqual(data["payload"], b"")

    def test_fail_deserialize_json(self):
        jws = JsonWebSignature()
        self.assertRaises(errors.DecodeError, jws.deserialize_json, None, "")
        self.assertRaises(errors.DecodeError, jws.deserialize_json, "[]", "")
        self.assertRaises(errors.DecodeError, jws.deserialize_json, "{}", "")

        # missing protected
        s = json.dumps({"payload": "YQ"})
        self.assertRaises(errors.DecodeError, jws.deserialize_json, s, "")

        # missing signature
        s = json.dumps({"payload": "YQ", "protected": "YQ"})
        self.assertRaises(errors.DecodeError, jws.deserialize_json, s, "")

    def test_validate_header(self):
        jws = JsonWebSignature(private_headers=[])
        protected = {"alg": "HS256", "invalid": "k"}
        header = {"protected": protected, "header": {"kid": "a"}}
        self.assertRaises(
            errors.InvalidHeaderParameterNameError,
            jws.serialize,
            header,
            b"hello",
            "secret",
        )
        jws = JsonWebSignature(private_headers=["invalid"])
        s = jws.serialize(header, b"hello", "secret")
        self.assertIsInstance(s, dict)

        jws = JsonWebSignature()
        s = jws.serialize(header, b"hello", "secret")
        self.assertIsInstance(s, dict)

    def test_ES512_alg(self):
        jws = JsonWebSignature()
        private_key = read_file_path("secp521r1-private.json")
        public_key = read_file_path("secp521r1-public.json")
        self.assertRaises(
            ValueError, jws.serialize, {"alg": "ES256"}, "hello", private_key
        )
        s = jws.serialize({"alg": "ES512"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "ES512")

    def test_ES256K_alg(self):
        jws = JsonWebSignature(algorithms=["ES256K"])
        private_key = read_file_path("secp256k1-private.pem")
        public_key = read_file_path("secp256k1-pub.pem")
        s = jws.serialize({"alg": "ES256K"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        self.assertEqual(payload, b"hello")
        self.assertEqual(header["alg"], "ES256K")
