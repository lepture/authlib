import os
import unittest
from authlib.jose import errors
from authlib.jose import OctKey, OKPKey
from authlib.jose import JsonWebEncryption
from authlib.common.encoding import urlsafe_b64encode
from tests.util import read_file_path


class JWETest(unittest.TestCase):
    def test_not_enough_segments(self):
        s = 'a.b.c'
        jwe = JsonWebEncryption()
        self.assertRaises(
            errors.DecodeError,
            jwe.deserialize_compact,
            s, None
        )

    def test_invalid_header(self):
        jwe = JsonWebEncryption()
        public_key = read_file_path('rsa_public.pem')
        self.assertRaises(
            errors.MissingAlgorithmError,
            jwe.serialize_compact, {}, 'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.serialize_compact, {'alg': 'invalid'}, 'a', public_key
        )
        self.assertRaises(
            errors.MissingEncryptionAlgorithmError,
            jwe.serialize_compact, {'alg': 'RSA-OAEP'}, 'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.serialize_compact, {'alg': 'RSA-OAEP', 'enc': 'invalid'},
            'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'zip': 'invalid'},
            'a', public_key
        )

    def test_not_supported_alg(self):
        public_key = read_file_path('rsa_public.pem')
        private_key = read_file_path('rsa_private.pem')

        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )

        jwe = JsonWebEncryption(algorithms=['RSA1_5', 'A256GCM'])
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA1_5', 'enc': 'A256GCM', 'zip': 'DEF'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.deserialize_compact,
            s, private_key,
        )

        jwe = JsonWebEncryption(algorithms=['RSA-OAEP', 'A192GCM'])
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A192GCM', 'zip': 'DEF'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.deserialize_compact,
            s, private_key,
        )

    def test_compact_rsa(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello',
            read_file_path('rsa_public.pem')
        )
        data = jwe.deserialize_compact(s, read_file_path('rsa_private.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RSA-OAEP')

    def test_with_zip_header(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A128CBC-HS256', 'zip': 'DEF'},
            'hello',
            read_file_path('rsa_public.pem')
        )
        data = jwe.deserialize_compact(s, read_file_path('rsa_private.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RSA-OAEP')

    def test_aes_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            'A128GCM', 'A192GCM', 'A256GCM'
        ]
        for s in sizes:
            alg = 'A{}KW'.format(s)
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ase_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'A128KW', 'enc': 'A128GCM'}
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', b'invalid-key'
        )

    def test_aes_gcm_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            'A128GCM', 'A192GCM', 'A256GCM'
        ]
        for s in sizes:
            alg = 'A{}GCMKW'.format(s)
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ase_gcm_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'A128GCMKW', 'enc': 'A128GCM'}
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', b'invalid-key'
        )

    def test_ecdh_key_agreement_computation(self):
        # https://tools.ietf.org/html/rfc7518#appendix-C
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        headers = {
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i",
        }
        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-ES']
        key = alg.prepare_key(alice_key)
        bob_key = alg.prepare_key(bob_key)
        public_key = bob_key.get_op_key('wrapKey')
        dk = alg.deliver(key, public_key, headers, 128)
        self.assertEqual(urlsafe_b64encode(dk), b'VqqN6vgjbSBcIijNcacQGg')

    def test_ecdh_es_jwe(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            protected = {'alg': alg, 'enc': 'A128GCM'}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_with_okp(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key('X25519', is_private=True)
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            protected = {'alg': alg, 'enc': 'A128GCM'}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_raise(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
        }
        data = jwe.serialize_compact(protected, b'hello', key)
        self.assertRaises(ValueError, jwe.deserialize_compact, data, key)

        key = OKPKey.generate_key('Ed25519', is_private=True)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key
        )

    def test_dir_alg(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(128, is_private=True)
        protected = {'alg': 'dir', 'enc': 'A128GCM'}
        data = jwe.serialize_compact(protected, b'hello', key)
        rv = jwe.deserialize_compact(data, key)
        self.assertEqual(rv['payload'], b'hello')

        key2 = OctKey.generate_key(256, is_private=True)
        self.assertRaises(ValueError, jwe.deserialize_compact, data, key2)

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key2
        )

    def test_dir_alg_c20p(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(256, is_private=True)
        protected = {'alg': 'dir', 'enc': 'C20P'}
        data = jwe.serialize_compact(protected, b'hello', key)
        rv = jwe.deserialize_compact(data, key)
        self.assertEqual(rv['payload'], b'hello')

        key2 = OctKey.generate_key(128, is_private=True)
        self.assertRaises(ValueError, jwe.deserialize_compact, data, key2)

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key2
        )
