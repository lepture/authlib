import unittest

from authlib.common.encoding import base64_to_int
from authlib.common.encoding import json_dumps
from authlib.jose import ECKey
from authlib.jose import JsonWebKey
from authlib.jose import KeySet
from authlib.jose import OctKey
from authlib.jose import OKPKey
from authlib.jose import RSAKey
from tests.util import read_file_path


class BaseTest(unittest.TestCase):
    def assertBase64IntEqual(self, x, y):
        self.assertEqual(base64_to_int(x), base64_to_int(y))


class OctKeyTest(BaseTest):
    def test_import_oct_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.5
        obj = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }
        key = OctKey.import_key(obj)
        new_obj = key.as_dict()
        self.assertEqual(obj["k"], new_obj["k"])
        self.assertIn("use", new_obj)

    def test_invalid_oct_key(self):
        self.assertRaises(ValueError, OctKey.import_key, {})

    def test_generate_oct_key(self):
        self.assertRaises(ValueError, OctKey.generate_key, 251)

        with self.assertRaises(ValueError) as cm:
            OctKey.generate_key(is_private=False)

        self.assertEqual(str(cm.exception), "oct key can not be generated as public")

        key = OctKey.generate_key()
        self.assertIn("kid", key.as_dict())
        self.assertNotIn("use", key.as_dict())

        key2 = OctKey.import_key(key, {"use": "sig"})
        self.assertIn("use", key2.as_dict())


class RSAKeyTest(BaseTest):
    def test_import_ssh_pem(self):
        raw = read_file_path("ssh_public.pem")
        key = RSAKey.import_key(raw)
        obj = key.as_dict()
        self.assertEqual(obj["kty"], "RSA")

    def test_rsa_public_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.3
        obj = read_file_path("jwk_public.json")
        key = RSAKey.import_key(obj)
        new_obj = key.as_dict()
        self.assertBase64IntEqual(new_obj["n"], obj["n"])
        self.assertBase64IntEqual(new_obj["e"], obj["e"])

    def test_rsa_private_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.4
        obj = read_file_path("jwk_private.json")
        key = RSAKey.import_key(obj)
        new_obj = key.as_dict(is_private=True)
        self.assertBase64IntEqual(new_obj["n"], obj["n"])
        self.assertBase64IntEqual(new_obj["e"], obj["e"])
        self.assertBase64IntEqual(new_obj["d"], obj["d"])
        self.assertBase64IntEqual(new_obj["p"], obj["p"])
        self.assertBase64IntEqual(new_obj["q"], obj["q"])
        self.assertBase64IntEqual(new_obj["dp"], obj["dp"])
        self.assertBase64IntEqual(new_obj["dq"], obj["dq"])
        self.assertBase64IntEqual(new_obj["qi"], obj["qi"])

    def test_rsa_private_key2(self):
        rsa_obj = read_file_path("jwk_private.json")
        obj = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": rsa_obj["n"],
            "d": rsa_obj["d"],
            "e": "AQAB",
        }
        key = RSAKey.import_key(obj)
        new_obj = key.as_dict(is_private=True)
        self.assertBase64IntEqual(new_obj["n"], obj["n"])
        self.assertBase64IntEqual(new_obj["e"], obj["e"])
        self.assertBase64IntEqual(new_obj["d"], obj["d"])
        self.assertBase64IntEqual(new_obj["p"], rsa_obj["p"])
        self.assertBase64IntEqual(new_obj["q"], rsa_obj["q"])
        self.assertBase64IntEqual(new_obj["dp"], rsa_obj["dp"])
        self.assertBase64IntEqual(new_obj["dq"], rsa_obj["dq"])
        self.assertBase64IntEqual(new_obj["qi"], rsa_obj["qi"])

    def test_invalid_rsa(self):
        self.assertRaises(ValueError, RSAKey.import_key, {"kty": "RSA"})
        rsa_obj = read_file_path("jwk_private.json")
        obj = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": rsa_obj["n"],
            "d": rsa_obj["d"],
            "p": rsa_obj["p"],
            "e": "AQAB",
        }
        self.assertRaises(ValueError, RSAKey.import_key, obj)

    def test_rsa_key_generate(self):
        self.assertRaises(ValueError, RSAKey.generate_key, 256)
        self.assertRaises(ValueError, RSAKey.generate_key, 2001)

        key1 = RSAKey.generate_key(is_private=True)
        self.assertIn(b"PRIVATE", key1.as_pem(is_private=True))
        self.assertIn(b"PUBLIC", key1.as_pem(is_private=False))

        key2 = RSAKey.generate_key(is_private=False)
        self.assertRaises(ValueError, key2.as_pem, True)
        self.assertIn(b"PUBLIC", key2.as_pem(is_private=False))


class ECKeyTest(BaseTest):
    def test_ec_public_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.1
        obj = read_file_path("secp521r1-public.json")
        key = ECKey.import_key(obj)
        new_obj = key.as_dict()
        self.assertEqual(new_obj["crv"], obj["crv"])
        self.assertBase64IntEqual(new_obj["x"], obj["x"])
        self.assertBase64IntEqual(new_obj["y"], obj["y"])
        self.assertEqual(key.as_json()[0], "{")

    def test_ec_private_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.2
        obj = read_file_path("secp521r1-private.json")
        key = ECKey.import_key(obj)
        new_obj = key.as_dict(is_private=True)
        self.assertEqual(new_obj["crv"], obj["crv"])
        self.assertBase64IntEqual(new_obj["x"], obj["x"])
        self.assertBase64IntEqual(new_obj["y"], obj["y"])
        self.assertBase64IntEqual(new_obj["d"], obj["d"])

    def test_invalid_ec(self):
        self.assertRaises(ValueError, ECKey.import_key, {"kty": "EC"})

    def test_ec_key_generate(self):
        self.assertRaises(ValueError, ECKey.generate_key, "Invalid")

        key1 = ECKey.generate_key("P-384", is_private=True)
        self.assertIn(b"PRIVATE", key1.as_pem(is_private=True))
        self.assertIn(b"PUBLIC", key1.as_pem(is_private=False))

        key2 = ECKey.generate_key("P-256", is_private=False)
        self.assertRaises(ValueError, key2.as_pem, True)
        self.assertIn(b"PUBLIC", key2.as_pem(is_private=False))


class OKPKeyTest(BaseTest):
    def test_import_okp_ssh_key(self):
        raw = read_file_path("ed25519-ssh.pub")
        key = OKPKey.import_key(raw)
        obj = key.as_dict()
        self.assertEqual(obj["kty"], "OKP")
        self.assertEqual(obj["crv"], "Ed25519")

    def test_import_okp_public_key(self):
        obj = {
            "x": "AD9E0JYnpV-OxZbd8aN1t4z71Vtf6JcJC7TYHT0HDbg",
            "crv": "Ed25519",
            "kty": "OKP",
        }
        key = OKPKey.import_key(obj)
        new_obj = key.as_dict()
        self.assertEqual(obj["x"], new_obj["x"])

    def test_import_okp_private_pem(self):
        raw = read_file_path("ed25519-pkcs8.pem")
        key = OKPKey.import_key(raw)
        obj = key.as_dict(is_private=True)
        self.assertEqual(obj["kty"], "OKP")
        self.assertEqual(obj["crv"], "Ed25519")
        self.assertIn("d", obj)

    def test_import_okp_private_dict(self):
        obj = {
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "crv": "Ed25519",
            "kty": "OKP",
        }
        key = OKPKey.import_key(obj)
        new_obj = key.as_dict(is_private=True)
        self.assertEqual(obj["d"], new_obj["d"])

    def test_okp_key_generate_pem(self):
        self.assertRaises(ValueError, OKPKey.generate_key, "invalid")

        key1 = OKPKey.generate_key("Ed25519", is_private=True)
        self.assertIn(b"PRIVATE", key1.as_pem(is_private=True))
        self.assertIn(b"PUBLIC", key1.as_pem(is_private=False))

        key2 = OKPKey.generate_key("X25519", is_private=False)
        self.assertRaises(ValueError, key2.as_pem, True)
        self.assertIn(b"PUBLIC", key2.as_pem(is_private=False))


class JWKTest(BaseTest):
    def test_generate_keys(self):
        key = JsonWebKey.generate_key(kty="oct", crv_or_size=256, is_private=True)
        self.assertEqual(key["kty"], "oct")

        key = JsonWebKey.generate_key(kty="EC", crv_or_size="P-256")
        self.assertEqual(key["kty"], "EC")

        key = JsonWebKey.generate_key(kty="RSA", crv_or_size=2048)
        self.assertEqual(key["kty"], "RSA")

        key = JsonWebKey.generate_key(kty="OKP", crv_or_size="Ed25519")
        self.assertEqual(key["kty"], "OKP")

    def test_import_keys(self):
        rsa_pub_pem = read_file_path("rsa_public.pem")
        self.assertRaises(ValueError, JsonWebKey.import_key, rsa_pub_pem, {"kty": "EC"})

        key = JsonWebKey.import_key(raw=rsa_pub_pem, options={"kty": "RSA"})
        self.assertIn("e", dict(key))
        self.assertIn("n", dict(key))

        key = JsonWebKey.import_key(raw=rsa_pub_pem)
        self.assertIn("e", dict(key))
        self.assertIn("n", dict(key))

    def test_import_key_set(self):
        jwks_public = read_file_path("jwks_public.json")
        key_set1 = JsonWebKey.import_key_set(jwks_public)
        key1 = key_set1.find_by_kid("abc")
        self.assertEqual(key1["e"], "AQAB")

        key_set2 = JsonWebKey.import_key_set(jwks_public["keys"])
        key2 = key_set2.find_by_kid("abc")
        self.assertEqual(key2["e"], "AQAB")

        key_set3 = JsonWebKey.import_key_set(json_dumps(jwks_public))
        key3 = key_set3.find_by_kid("abc")
        self.assertEqual(key3["e"], "AQAB")

        self.assertRaises(ValueError, JsonWebKey.import_key_set, "invalid")

    def test_thumbprint(self):
        # https://tools.ietf.org/html/rfc7638#section-3.1
        data = read_file_path("thumbprint_example.json")
        key = JsonWebKey.import_key(data)
        expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        self.assertEqual(key.thumbprint(), expected)

    def test_key_set(self):
        key = RSAKey.generate_key(is_private=True)
        key_set = KeySet([key])
        obj = key_set.as_dict()["keys"][0]
        self.assertIn("kid", obj)
        self.assertEqual(key_set.as_json()[0], "{")
