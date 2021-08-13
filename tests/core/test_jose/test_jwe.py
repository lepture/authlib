import os
import unittest
from collections import OrderedDict

from authlib.jose import errors, ECKey
from authlib.jose import OctKey, OKPKey
from authlib.jose import JsonWebEncryption
from authlib.common.encoding import urlsafe_b64encode, json_b64encode, to_bytes
from authlib.jose.errors import InvalidEncryptionAlgorithmForECDH1PUWithKeyWrappingError
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

    def test_aes_jwe_invalid_key(self):
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

    def test_aes_gcm_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'A128GCMKW', 'enc': 'A128GCM'}
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', b'invalid-key'
        )

    def test_ecdh_es_key_agreement_computation(self):
        # https://tools.ietf.org/html/rfc7518#appendix-C
        alice_ephemeral_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        bob_static_key = {
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
            "epk":
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                    "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
                }
        }

        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-ES']
        enc = JsonWebEncryption.ENC_REGISTRY['A128GCM']

        alice_ephemeral_key = alg.prepare_key(alice_ephemeral_key)
        bob_static_key = alg.prepare_key(bob_static_key)

        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key('wrapKey')
        bob_static_pubkey = bob_static_key.get_op_key('wrapKey')

        # Derived key computation at Alice

        # Step-by-step methods verification
        _shared_key_at_alice = alice_ephemeral_key.exchange_shared_key(bob_static_pubkey)
        self.assertEqual(
            _shared_key_at_alice,
            bytes([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
                   251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196])
        )

        _fixed_info_at_alice = alg.compute_fixed_info(headers, enc.key_size)
        self.assertEqual(
            _fixed_info_at_alice,
            bytes([0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65,
                   108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128])
        )

        _dk_at_alice = alg.compute_derived_key(_shared_key_at_alice, _fixed_info_at_alice, enc.key_size)
        self.assertEqual(_dk_at_alice, bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]))
        self.assertEqual(urlsafe_b64encode(_dk_at_alice), b'VqqN6vgjbSBcIijNcacQGg')

        # All-in-one method verification
        dk_at_alice = alg.deliver(alice_ephemeral_key, bob_static_pubkey, headers, enc.key_size)
        self.assertEqual(dk_at_alice, bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]))
        self.assertEqual(urlsafe_b64encode(dk_at_alice), b'VqqN6vgjbSBcIijNcacQGg')

        # Derived key computation at Bob

        # Step-by-step methods verification
        _shared_key_at_bob = bob_static_key.exchange_shared_key(alice_ephemeral_pubkey)
        self.assertEqual(_shared_key_at_bob, _shared_key_at_alice)

        _fixed_info_at_bob = alg.compute_fixed_info(headers, enc.key_size)
        self.assertEqual(_fixed_info_at_bob, _fixed_info_at_alice)

        _dk_at_bob = alg.compute_derived_key(_shared_key_at_bob, _fixed_info_at_bob, enc.key_size)
        self.assertEqual(_dk_at_bob, _dk_at_alice)

        # All-in-one method verification
        dk_at_bob = alg.deliver(bob_static_key, alice_ephemeral_pubkey, headers, enc.key_size)
        self.assertEqual(dk_at_bob, dk_at_alice)

    def test_ecdh_es_jwe_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }

        for enc in [
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
            'A128GCM',
            'A192GCM',
            'A256GCM',
        ]:
            protected = {'alg': 'ECDH-ES', 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_jwe_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }

        for alg in [
            'ECDH-ES+A128KW',
            'ECDH-ES+A192KW',
            'ECDH-ES+A256KW',
        ]:
            for enc in [
                'A128CBC-HS256',
                'A192CBC-HS384',
                'A256CBC-HS512',
                'A128GCM',
                'A192GCM',
                'A256GCM',
            ]:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_jwe_with_okp_key_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key('X25519', is_private=True)

        for enc in [
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
            'A128GCM',
            'A192GCM',
            'A256GCM',
        ]:
            protected = {'alg': 'ECDH-ES', 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_jwe_with_okp_key_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key('X25519', is_private=True)

        for alg in [
            'ECDH-ES+A128KW',
            'ECDH-ES+A192KW',
            'ECDH-ES+A256KW',
        ]:
            for enc in [
                'A128CBC-HS256',
                'A192CBC-HS384',
                'A256CBC-HS512',
                'A128GCM',
                'A192GCM',
                'A256GCM',
            ]:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_decryption_with_public_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}

        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }
        data = jwe.serialize_compact(protected, b'hello', key)
        self.assertRaises(
            ValueError,
            jwe.deserialize_compact,
            data, key
        )

    def test_ecdh_es_encryption_fails_if_key_curve_is_inappropriate(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}

        key = OKPKey.generate_key('Ed25519', is_private=False)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key
        )

    def test_ecdh_1pu_key_agreement_computation_appx_a(self):
        # https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-A
        alice_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        alice_ephemeral_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }

        headers = {
            "alg": "ECDH-1PU",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
            }
        }

        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-1PU']
        enc = JsonWebEncryption.ENC_REGISTRY['A256GCM']

        alice_static_key = alg.prepare_key(alice_static_key)
        bob_static_key = alg.prepare_key(bob_static_key)
        alice_ephemeral_key = alg.prepare_key(alice_ephemeral_key)

        alice_static_pubkey = alice_static_key.get_op_key('wrapKey')
        bob_static_pubkey = bob_static_key.get_op_key('wrapKey')
        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key('wrapKey')

        # Derived key computation at Alice

        # Step-by-step methods verification
        _shared_key_e_at_alice = alice_ephemeral_key.exchange_shared_key(bob_static_pubkey)
        self.assertEqual(
            _shared_key_e_at_alice,
            b'\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c' +
            b'\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4'
        )

        _shared_key_s_at_alice = alice_static_key.exchange_shared_key(bob_static_pubkey)
        self.assertEqual(
            _shared_key_s_at_alice,
            b'\xe3\xca\x34\x74\x38\x4c\x9f\x62\xb3\x0b\xfd\x4c\x68\x8b\x3e\x7d' +
            b'\x41\x10\xa1\xb4\xba\xdc\x3c\xc5\x4e\xf7\xb8\x12\x41\xef\xd5\x0d'
        )

        _shared_key_at_alice = alg.compute_shared_key(_shared_key_e_at_alice, _shared_key_s_at_alice)
        self.assertEqual(
            _shared_key_at_alice,
            b'\x9e\x56\xd9\x1d\x81\x71\x35\xd3\x72\x83\x42\x83\xbf\x84\x26\x9c' +
            b'\xfb\x31\x6e\xa3\xda\x80\x6a\x48\xf6\xda\xa7\x79\x8c\xfe\x90\xc4' +
            b'\xe3\xca\x34\x74\x38\x4c\x9f\x62\xb3\x0b\xfd\x4c\x68\x8b\x3e\x7d' +
            b'\x41\x10\xa1\xb4\xba\xdc\x3c\xc5\x4e\xf7\xb8\x12\x41\xef\xd5\x0d'
        )

        _fixed_info_at_alice = alg.compute_fixed_info(headers, enc.key_size, None)
        self.assertEqual(
            _fixed_info_at_alice,
            b'\x00\x00\x00\x07\x41\x32\x35\x36\x47\x43\x4d\x00\x00\x00\x05\x41' +
            b'\x6c\x69\x63\x65\x00\x00\x00\x03\x42\x6f\x62\x00\x00\x01\x00'
        )

        _dk_at_alice = alg.compute_derived_key(_shared_key_at_alice, _fixed_info_at_alice, enc.key_size)
        self.assertEqual(
            _dk_at_alice,
            b'\x6c\xaf\x13\x72\x3d\x14\x85\x0a\xd4\xb4\x2c\xd6\xdd\xe9\x35\xbf' +
            b'\xfd\x2f\xff\x00\xa9\xba\x70\xde\x05\xc2\x03\xa5\xe1\x72\x2c\xa7'
        )
        self.assertEqual(urlsafe_b64encode(_dk_at_alice), b'bK8Tcj0UhQrUtCzW3ek1v_0v_wCpunDeBcIDpeFyLKc')

        # All-in-one method verification
        dk_at_alice = alg.deliver_at_sender(
            alice_static_key, alice_ephemeral_key, bob_static_pubkey, headers, enc.key_size, None)
        self.assertEqual(urlsafe_b64encode(dk_at_alice), b'bK8Tcj0UhQrUtCzW3ek1v_0v_wCpunDeBcIDpeFyLKc')

        # Derived key computation at Bob

        # Step-by-step methods verification
        _shared_key_e_at_bob = bob_static_key.exchange_shared_key(alice_ephemeral_pubkey)
        self.assertEqual(_shared_key_e_at_bob, _shared_key_e_at_alice)

        _shared_key_s_at_bob = bob_static_key.exchange_shared_key(alice_static_pubkey)
        self.assertEqual(_shared_key_s_at_bob, _shared_key_s_at_alice)

        _shared_key_at_bob = alg.compute_shared_key(_shared_key_e_at_bob, _shared_key_s_at_bob)
        self.assertEqual(_shared_key_at_bob, _shared_key_at_alice)

        _fixed_info_at_bob = alg.compute_fixed_info(headers, enc.key_size, None)
        self.assertEqual(_fixed_info_at_bob, _fixed_info_at_alice)

        _dk_at_bob = alg.compute_derived_key(_shared_key_at_bob, _fixed_info_at_bob, enc.key_size)
        self.assertEqual(_dk_at_bob, _dk_at_alice)

        # All-in-one method verification
        dk_at_bob = alg.deliver_at_recipient(
            bob_static_key, alice_static_pubkey, alice_ephemeral_pubkey, headers, enc.key_size, None)
        self.assertEqual(dk_at_bob, dk_at_alice)

    def test_ecdh_1pu_key_agreement_computation_appx_b(self):
        # https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B
        alice_static_key = {
            "kty": "OKP",
            "crv": "X25519",
            "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
            "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"
        }
        bob_static_key = {
            "kty": "OKP",
            "crv": "X25519",
            "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
            "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"
        }
        charlie_static_key = {
            "kty": "OKP",
            "crv": "X25519",
            "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
            "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE"
        }
        alice_ephemeral_key = {
            "kty": "OKP",
            "crv": "X25519",
            "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"
        }

        headers = OrderedDict({
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": OrderedDict({
                "kty": "OKP",
                "crv": "X25519",
                "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"
            })
        })

        cek = b'\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0' \
              b'\xef\xee\xed\xec\xeb\xea\xe9\xe8\xe7\xe6\xe5\xe4\xe3\xe2\xe1\xe0' \
              b'\xdf\xde\xdd\xdc\xdb\xda\xd9\xd8\xd7\xd6\xd5\xd4\xd3\xd2\xd1\xd0' \
              b'\xcf\xce\xcd\xcc\xcb\xca\xc9\xc8\xc7\xc6\xc5\xc4\xc3\xc2\xc1\xc0'

        iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        payload = b'Three is a magic number.'

        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-1PU+A128KW']
        enc = JsonWebEncryption.ENC_REGISTRY['A256CBC-HS512']

        alice_static_key = OKPKey.import_key(alice_static_key)
        bob_static_key = OKPKey.import_key(bob_static_key)
        charlie_static_key = OKPKey.import_key(charlie_static_key)
        alice_ephemeral_key = OKPKey.import_key(alice_ephemeral_key)

        alice_static_pubkey = alice_static_key.get_op_key('wrapKey')
        bob_static_pubkey = bob_static_key.get_op_key('wrapKey')
        charlie_static_pubkey = charlie_static_key.get_op_key('wrapKey')
        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key('wrapKey')

        protected_segment = json_b64encode(headers)
        aad = to_bytes(protected_segment, 'ascii')

        ciphertext, tag = enc.encrypt(payload, aad, iv, cek)
        self.assertEqual(urlsafe_b64encode(ciphertext), b'Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw')
        self.assertEqual(urlsafe_b64encode(tag), b'HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ')

        # Derived key computation at Alice for Bob

        # Step-by-step methods verification
        _shared_key_e_at_alice_for_bob = alice_ephemeral_key.exchange_shared_key(bob_static_pubkey)
        self.assertEqual(
            _shared_key_e_at_alice_for_bob,
            b'\x32\x81\x08\x96\xe0\xfe\x4d\x57\x0e\xd1\xac\xfc\xed\xf6\x71\x17' +
            b'\xdc\x19\x4e\xd5\xda\xac\x21\xd8\xff\x7a\xf3\x24\x46\x94\x89\x7f'
        )

        _shared_key_s_at_alice_for_bob = alice_static_key.exchange_shared_key(bob_static_pubkey)
        self.assertEqual(
            _shared_key_s_at_alice_for_bob,
            b'\x21\x57\x61\x2c\x90\x48\xed\xfa\xe7\x7c\xb2\xe4\x23\x71\x40\x60' +
            b'\x59\x67\xc0\x5c\x7f\x77\xa4\x8e\xea\xf2\xcf\x29\xa5\x73\x7c\x4a'
        )

        _shared_key_at_alice_for_bob = alg.compute_shared_key(_shared_key_e_at_alice_for_bob,
                                                               _shared_key_s_at_alice_for_bob)
        self.assertEqual(
            _shared_key_at_alice_for_bob,
            b'\x32\x81\x08\x96\xe0\xfe\x4d\x57\x0e\xd1\xac\xfc\xed\xf6\x71\x17' +
            b'\xdc\x19\x4e\xd5\xda\xac\x21\xd8\xff\x7a\xf3\x24\x46\x94\x89\x7f' +
            b'\x21\x57\x61\x2c\x90\x48\xed\xfa\xe7\x7c\xb2\xe4\x23\x71\x40\x60' +
            b'\x59\x67\xc0\x5c\x7f\x77\xa4\x8e\xea\xf2\xcf\x29\xa5\x73\x7c\x4a'
        )

        _fixed_info_at_alice_for_bob = alg.compute_fixed_info(headers, alg.key_size, tag)
        self.assertEqual(
            _fixed_info_at_alice_for_bob,
            b'\x00\x00\x00\x0f\x45\x43\x44\x48\x2d\x31\x50\x55\x2b\x41\x31\x32' +
            b'\x38\x4b\x57\x00\x00\x00\x05\x41\x6c\x69\x63\x65\x00\x00\x00\x0f' +
            b'\x42\x6f\x62\x20\x61\x6e\x64\x20\x43\x68\x61\x72\x6c\x69\x65\x00' +
            b'\x00\x00\x80\x00\x00\x00\x20\x1c\xb6\xf8\x7d\x39\x66\xf2\xca\x46' +
            b'\x9a\x28\xf7\x47\x23\xac\xda\x02\x78\x0e\x91\xcc\xe2\x18\x55\x47' +
            b'\x07\x45\xfe\x11\x9b\xdd\x64'
        )

        _dk_at_alice_for_bob = alg.compute_derived_key(_shared_key_at_alice_for_bob,
                                                        _fixed_info_at_alice_for_bob,
                                                        alg.key_size)
        self.assertEqual(_dk_at_alice_for_bob, b'\xdf\x4c\x37\xa0\x66\x83\x06\xa1\x1e\x3d\x6b\x00\x74\xb5\xd8\xdf')

        # All-in-one method verification
        dk_at_alice_for_bob = alg.deliver_at_sender(
            alice_static_key, alice_ephemeral_key, bob_static_pubkey, headers, alg.key_size, tag)
        self.assertEqual(dk_at_alice_for_bob, b'\xdf\x4c\x37\xa0\x66\x83\x06\xa1\x1e\x3d\x6b\x00\x74\xb5\xd8\xdf')

        kek_at_alice_for_bob = alg.aeskw.prepare_key(dk_at_alice_for_bob)
        wrapped_for_bob = alg.aeskw.wrap_cek(cek, kek_at_alice_for_bob)
        ek_for_bob = wrapped_for_bob['ek']
        self.assertEqual(
            urlsafe_b64encode(ek_for_bob),
            b'pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN')

        # Derived key computation at Alice for Charlie

        # Step-by-step methods verification
        _shared_key_e_at_alice_for_charlie = alice_ephemeral_key.exchange_shared_key(charlie_static_pubkey)
        self.assertEqual(
            _shared_key_e_at_alice_for_charlie,
            b'\x89\xdc\xfe\x4c\x37\xc1\xdc\x02\x71\xf3\x46\xb5\xb3\xb1\x9c\x3b' +
            b'\x70\x5c\xa2\xa7\x2f\x9a\x23\x77\x85\xc3\x44\x06\xfc\xb7\x5f\x10'
        )

        _shared_key_s_at_alice_for_charlie = alice_static_key.exchange_shared_key(charlie_static_pubkey)
        self.assertEqual(
            _shared_key_s_at_alice_for_charlie,
            b'\x78\xfe\x63\xfc\x66\x1c\xf8\xd1\x8f\x92\xa8\x42\x2a\x64\x18\xe4' +
            b'\xed\x5e\x20\xa9\x16\x81\x85\xfd\xee\xdc\xa1\xc3\xd8\xe6\xa6\x1c'
        )

        _shared_key_at_alice_for_charlie = alg.compute_shared_key(_shared_key_e_at_alice_for_charlie,
                                                                  _shared_key_s_at_alice_for_charlie)
        self.assertEqual(
            _shared_key_at_alice_for_charlie,
            b'\x89\xdc\xfe\x4c\x37\xc1\xdc\x02\x71\xf3\x46\xb5\xb3\xb1\x9c\x3b' +
            b'\x70\x5c\xa2\xa7\x2f\x9a\x23\x77\x85\xc3\x44\x06\xfc\xb7\x5f\x10' +
            b'\x78\xfe\x63\xfc\x66\x1c\xf8\xd1\x8f\x92\xa8\x42\x2a\x64\x18\xe4' +
            b'\xed\x5e\x20\xa9\x16\x81\x85\xfd\xee\xdc\xa1\xc3\xd8\xe6\xa6\x1c'
        )

        _fixed_info_at_alice_for_charlie = alg.compute_fixed_info(headers, alg.key_size, tag)
        self.assertEqual(_fixed_info_at_alice_for_charlie, _fixed_info_at_alice_for_bob)

        _dk_at_alice_for_charlie = alg.compute_derived_key(_shared_key_at_alice_for_charlie,
                                                           _fixed_info_at_alice_for_charlie,
                                                           alg.key_size)
        self.assertEqual(_dk_at_alice_for_charlie, b'\x57\xd8\x12\x6f\x1b\x7e\xc4\xcc\xb0\x58\x4d\xac\x03\xcb\x27\xcc')

        # All-in-one method verification
        dk_at_alice_for_charlie = alg.deliver_at_sender(
            alice_static_key, alice_ephemeral_key, charlie_static_pubkey, headers, alg.key_size, tag)
        self.assertEqual(dk_at_alice_for_charlie, b'\x57\xd8\x12\x6f\x1b\x7e\xc4\xcc\xb0\x58\x4d\xac\x03\xcb\x27\xcc')

        kek_at_alice_for_charlie = alg.aeskw.prepare_key(dk_at_alice_for_charlie)
        wrapped_for_charlie = alg.aeskw.wrap_cek(cek, kek_at_alice_for_charlie)
        ek_for_charlie = wrapped_for_charlie['ek']
        self.assertEqual(
            urlsafe_b64encode(ek_for_charlie),
            b'56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE')

        # Derived key computation at Bob for Alice

        # Step-by-step methods verification
        _shared_key_e_at_bob_for_alice = bob_static_key.exchange_shared_key(alice_ephemeral_pubkey)
        self.assertEqual(_shared_key_e_at_bob_for_alice, _shared_key_e_at_alice_for_bob)

        _shared_key_s_at_bob_for_alice = bob_static_key.exchange_shared_key(alice_static_pubkey)
        self.assertEqual(_shared_key_s_at_bob_for_alice, _shared_key_s_at_alice_for_bob)

        _shared_key_at_bob_for_alice = alg.compute_shared_key(_shared_key_e_at_bob_for_alice,
                                                              _shared_key_s_at_bob_for_alice)
        self.assertEqual(_shared_key_at_bob_for_alice, _shared_key_at_alice_for_bob)

        _fixed_info_at_bob_for_alice = alg.compute_fixed_info(headers, alg.key_size, tag)
        self.assertEqual(_fixed_info_at_bob_for_alice, _fixed_info_at_alice_for_bob)

        _dk_at_bob_for_alice = alg.compute_derived_key(_shared_key_at_bob_for_alice,
                                                       _fixed_info_at_bob_for_alice,
                                                       alg.key_size)
        self.assertEqual(_dk_at_bob_for_alice, _dk_at_alice_for_bob)

        # All-in-one method verification
        dk_at_bob_for_alice = alg.deliver_at_recipient(
            bob_static_key, alice_static_pubkey, alice_ephemeral_pubkey, headers, alg.key_size, tag)
        self.assertEqual(dk_at_bob_for_alice, dk_at_alice_for_bob)

        kek_at_bob_for_alice = alg.aeskw.prepare_key(dk_at_bob_for_alice)
        cek_unwrapped_by_bob = alg.aeskw.unwrap(enc, ek_for_bob, headers, kek_at_bob_for_alice)
        self.assertEqual(cek_unwrapped_by_bob, cek)

        payload_decrypted_by_bob = enc.decrypt(ciphertext, aad, iv, tag, cek_unwrapped_by_bob)
        self.assertEqual(payload_decrypted_by_bob, payload)

        # Derived key computation at Charlie for Alice

        # Step-by-step methods verification
        _shared_key_e_at_charlie_for_alice = charlie_static_key.exchange_shared_key(alice_ephemeral_pubkey)
        self.assertEqual(_shared_key_e_at_charlie_for_alice, _shared_key_e_at_alice_for_charlie)

        _shared_key_s_at_charlie_for_alice = charlie_static_key.exchange_shared_key(alice_static_pubkey)
        self.assertEqual(_shared_key_s_at_charlie_for_alice, _shared_key_s_at_alice_for_charlie)

        _shared_key_at_charlie_for_alice = alg.compute_shared_key(_shared_key_e_at_charlie_for_alice,
                                                                  _shared_key_s_at_charlie_for_alice)
        self.assertEqual(_shared_key_at_charlie_for_alice, _shared_key_at_alice_for_charlie)

        _fixed_info_at_charlie_for_alice = alg.compute_fixed_info(headers, alg.key_size, tag)
        self.assertEqual(_fixed_info_at_charlie_for_alice, _fixed_info_at_alice_for_charlie)

        _dk_at_charlie_for_alice = alg.compute_derived_key(_shared_key_at_charlie_for_alice,
                                                           _fixed_info_at_charlie_for_alice,
                                                           alg.key_size)
        self.assertEqual(_dk_at_charlie_for_alice, _dk_at_alice_for_charlie)

        # All-in-one method verification
        dk_at_charlie_for_alice = alg.deliver_at_recipient(
            charlie_static_key, alice_static_pubkey, alice_ephemeral_pubkey, headers, alg.key_size, tag)
        self.assertEqual(dk_at_charlie_for_alice, dk_at_alice_for_charlie)

        kek_at_charlie_for_alice = alg.aeskw.prepare_key(dk_at_charlie_for_alice)
        cek_unwrapped_by_charlie = alg.aeskw.unwrap(enc, ek_for_charlie, headers, kek_at_charlie_for_alice)
        self.assertEqual(cek_unwrapped_by_charlie, cek)

        payload_decrypted_by_charlie = enc.decrypt(ciphertext, aad, iv, tag, cek_unwrapped_by_charlie)
        self.assertEqual(payload_decrypted_by_charlie, payload)

    def test_ecdh_1pu_jwe_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }

        for enc in [
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
            'A128GCM',
            'A192GCM',
            'A256GCM',
        ]:
            protected = {'alg': 'ECDH-1PU', 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
            rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_jwe_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }

        for alg in [
            'ECDH-1PU+A128KW',
            'ECDH-1PU+A192KW',
            'ECDH-1PU+A256KW',
        ]:
            for enc in [
                'A128CBC-HS256',
                'A192CBC-HS384',
                'A256CBC-HS512',
            ]:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
                rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_jwe_with_okp_keys_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        alice_key = OKPKey.generate_key('X25519', is_private=True)
        bob_key = OKPKey.generate_key('X25519', is_private=True)

        for enc in [
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
            'A128GCM',
            'A192GCM',
            'A256GCM',
        ]:
            protected = {'alg': 'ECDH-1PU', 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
            rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_jwe_with_okp_keys_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        alice_key = OKPKey.generate_key('X25519', is_private=True)
        bob_key = OKPKey.generate_key('X25519', is_private=True)

        for alg in [
            'ECDH-1PU+A128KW',
            'ECDH-1PU+A192KW',
            'ECDH-1PU+A256KW',
        ]:
            for enc in [
                'A128CBC-HS256',
                'A192CBC-HS384',
                'A256CBC-HS512',
            ]:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
                rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_encryption_fails_if_not_aes_cbc_hmac_sha2_enc_is_used_with_kw(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }

        for alg in [
            'ECDH-1PU+A128KW',
            'ECDH-1PU+A192KW',
            'ECDH-1PU+A256KW',
        ]:
            for enc in [
                'A128GCM',
                'A192GCM',
                'A256GCM',
            ]:
                protected = {'alg': alg, 'enc': enc}
                self.assertRaises(
                    InvalidEncryptionAlgorithmForECDH1PUWithKeyWrappingError,
                    jwe.serialize_compact,
                    protected, b'hello', bob_key, sender_key=alice_key
                )

    def test_ecdh_1pu_encryption_with_public_sender_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_decryption_with_public_recipient_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }
        data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
        self.assertRaises(
            ValueError,
            jwe.deserialize_compact,
            data, bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_encryption_fails_if_key_types_are_different(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = ECKey.generate_key('P-256', is_private=True)
        bob_key = OKPKey.generate_key('X25519', is_private=False)
        self.assertRaises(
            Exception,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = OKPKey.generate_key('X25519', is_private=True)
        bob_key = ECKey.generate_key('P-256', is_private=False)
        self.assertRaises(
            Exception,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_encryption_fails_if_keys_curves_are_different(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = ECKey.generate_key('P-256', is_private=True)
        bob_key = ECKey.generate_key('secp256k1', is_private=False)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = ECKey.generate_key('P-384', is_private=True)
        bob_key = ECKey.generate_key('P-521', is_private=False)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = OKPKey.generate_key('X25519', is_private=True)
        bob_key = OKPKey.generate_key('X448', is_private=False)
        self.assertRaises(
            TypeError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_encryption_fails_if_key_points_are_not_actually_on_same_curve(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "aDHtGkIYyhR5geqfMaFL0T9cG4JEMI8nyMFJA7gRUDs",
            "y": "AjGN5_f-aCt4vYg74my6n1ALIq746nlc_httIgcBSYY",
            "d": "Sim3EIzXsWaWu9QW8yKVHwxBM5CTlnrVU_Eq-y_KRQA"
        }  # the point is indeed on P-256 curve
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "5ZFnZbs_BtLBIZxwt5hS7SBDtI2a-dJ871dJ8ZnxZ6c",
            "y": "K0srqSkbo1Yeckr0YoQA8r_rOz0ZUStiv3mc1qn46pg"
        }  # the point is not on P-256 curve but is actually on secp256k1 curve

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = {
            "kty": "EC",
            "crv": "P-521",
            "x": "1JDMOjnMgASo01PVHRcyCDtE6CLgKuwXLXLbdLGxpdubLuHYBa0KAepyimnxCWsX",
            "y": "w7BSC8Xb3XgMMfE7IFCJpoOmx1Sf3T3_3OZ4CrF6_iCFAw4VOdFYR42OnbKMFG--",
            "d": "lCkpFBaVwHzfHtkJEV3PzxefObOPnMgUjNZSLryqC5AkERgXT3-DZLEi6eBzq5gk"
        }  # the point is not on P-521 curve but is actually on P-384 curve
        bob_key = {
            "kty": "EC",
            "crv": "P-521",
            "x": "Cd6rinJdgS4WJj6iaNyXiVhpMbhZLmPykmrnFhIad04B3ulf5pURb5v9mx21c_Cv8Q1RBOptwleLg5Qjq2J1qa4",
            "y": "hXo9p1EjW6W4opAQdmfNgyxztkNxYwn9L4FVTLX51KNEsW0aqueLm96adRmf0HoGIbNhIdcIlXOKlRUHqgunDkM"
        }  # the point is indeed on P-521 curve

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = OKPKey.import_key({
            "kty": "OKP",
            "crv": "X25519",
            "x": "TAB1oIsjPob3guKwTEeQsAsupSRPdXdxHhnV8JrVJTA",
            "d": "kO2LzPr4vLg_Hn-7_MDq66hJZgvTIkzDG4p6nCsgNHk"
        })  # the point is indeed on X25519 curve
        bob_key = OKPKey.import_key({
            "kty": "OKP",
            "crv": "X25519",
            "x": "lVHcPx4R9bExaoxXZY9tAq7SNW9pJKCoVQxURLtkAs3Dg5ZRxcjhf0JUyg2lod5OGDptJ7wowwY"
        })  # the point is not on X25519 curve but is actually on X448 curve

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

        alice_key = OKPKey.import_key({
            "kty": "OKP",
            "crv": "X448",
            "x": "TAB1oIsjPob3guKwTEeQsAsupSRPdXdxHhnV8JrVJTA",
            "d": "kO2LzPr4vLg_Hn-7_MDq66hJZgvTIkzDG4p6nCsgNHk"
        })  # the point is not on X448 curve but is actually on X25519 curve
        bob_key = OKPKey.import_key({
            "kty": "OKP",
            "crv": "X448",
            "x": "lVHcPx4R9bExaoxXZY9tAq7SNW9pJKCoVQxURLtkAs3Dg5ZRxcjhf0JUyg2lod5OGDptJ7wowwY"
        })  # the point is indeed on X448 curve

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_encryption_fails_if_keys_curve_is_inappropriate(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = OKPKey.generate_key('Ed25519', is_private=True)  # use Ed25519 instead of X25519
        bob_key = OKPKey.generate_key('Ed25519', is_private=False)  # use Ed25519 instead of X25519
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
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

    def test_dir_alg_xc20p(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(256, is_private=True)
        protected = {'alg': 'dir', 'enc': 'XC20P'}
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

    def test_xc20p_content_encryption_decryption(self):
        # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
        enc = JsonWebEncryption.ENC_REGISTRY['XC20P']

        plaintext = bytes.fromhex(
            '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
            '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
            '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
            '637265656e20776f756c642062652069742e'
        )
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        key = bytes.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
        iv = bytes.fromhex('404142434445464748494a4b4c4d4e4f5051525354555657')

        ciphertext, tag = enc.encrypt(plaintext, aad, iv, key)
        self.assertEqual(
            ciphertext,
            bytes.fromhex(
                'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
                '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
                '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
                '21f9664c97637da9768812f615c68b13b52e'
            )
        )
        self.assertEqual(tag, bytes.fromhex('c0875924c1c7987947deafd8780acf49'))

        decrypted_plaintext = enc.decrypt(ciphertext, aad, iv, tag, key)
        self.assertEqual(decrypted_plaintext, plaintext)
