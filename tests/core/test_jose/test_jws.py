import unittest
import json
from authlib.jose import JsonWebSignature, JWS_ALGORITHMS, JWE_ALGORITHMS
from authlib.jose import errors
from authlib.jose.rfc8037 import JWS_ALGORITHMS as RFC8037_ALGORITHMS
from tests.util import read_file_path


class JWSTest(unittest.TestCase):
    def test_register_invalid_algorithms(self):
        self.assertRaises(
            ValueError,
            JsonWebSignature,
            ['INVALID']
        )

        jws = JsonWebSignature(algorithms=[])
        self.assertRaises(
            ValueError,
            jws.register_algorithm,
            JWE_ALGORITHMS[0]
        )

    def test_invalid_input(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        self.assertRaises(errors.DecodeError, jws.deserialize, 'a', 'k')
        self.assertRaises(errors.DecodeError, jws.deserialize, 'a.b.c', 'k')
        self.assertRaises(
            errors.DecodeError, jws.deserialize, 'YQ.YQ.YQ', 'k')  # a
        self.assertRaises(
            errors.DecodeError, jws.deserialize, 'W10.a.YQ', 'k')  # []
        self.assertRaises(
            errors.DecodeError, jws.deserialize, 'e30.a.YQ', 'k')  # {}
        self.assertRaises(
            errors.DecodeError, jws.deserialize, 'eyJhbGciOiJzIn0.a.YQ', 'k')
        self.assertRaises(
            errors.DecodeError, jws.deserialize, 'eyJhbGciOiJzIn0.YQ.a', 'k')

    def test_invalid_alg(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.deserialize, 'eyJhbGciOiJzIn0.YQ.YQ', 'k')
        self.assertRaises(
            errors.MissingAlgorithmError,
            jws.serialize, {}, '', 'k'
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.serialize, {'alg': 's'}, '', 'k'
        )

    def test_bad_signature(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        s = 'eyJhbGciOiJIUzI1NiJ9.YQ.YQ'
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, 'k')

    def test_not_supported_alg(self):
        jws = JsonWebSignature(algorithms=['HS256'])
        s = jws.serialize({'alg': 'HS256'}, 'hello', 'secret')

        jws = JsonWebSignature(algorithms=['RS256'])
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            lambda: jws.serialize({'alg': 'HS256'}, 'hello', 'secret')
        )

        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.deserialize,
            s, 'secret'
        )

    def test_compact_jws(self):
        jws = JsonWebSignature(algorithms=['HS256'])
        s = jws.serialize({'alg': 'HS256'}, 'hello', 'secret')
        data = jws.deserialize(s, 'secret')
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'HS256')
        self.assertNotIn('signature', data)

    def test_compact_rsa(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        private_key = read_file_path('rsa_private.pem')
        public_key = read_file_path('rsa_public.pem')
        s = jws.serialize({'alg': 'RS256'}, 'hello', private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RS256')

        ssh_pub_key = read_file_path('ssh_public.pem')
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, ssh_pub_key)

    def test_compact_rsa_pss(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        private_key = read_file_path('rsa_private.pem')
        public_key = read_file_path('rsa_public.pem')
        s = jws.serialize({'alg': 'PS256'}, 'hello', private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'PS256')
        ssh_pub_key = read_file_path('ssh_public.pem')
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, ssh_pub_key)

    def test_compact_none(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        s = jws.serialize({'alg': 'none'}, 'hello', '')
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, '')

    def test_flattened_json_jws(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        protected = {'alg': 'HS256'}
        header = {'protected': protected, 'header': {'kid': 'a'}}
        s = jws.serialize(header, 'hello', 'secret')
        self.assertIsInstance(s, dict)

        data = jws.deserialize(s, 'secret')
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'HS256')
        self.assertNotIn('protected', data)

    def test_nested_json_jws(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        protected = {'alg': 'HS256'}
        header = {'protected': protected, 'header': {'kid': 'a'}}
        s = jws.serialize([header], 'hello', 'secret')
        self.assertIsInstance(s, dict)
        self.assertIn('signatures', s)

        data = jws.deserialize(s, 'secret')
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header[0]['alg'], 'HS256')
        self.assertNotIn('signatures', data)

        # test bad signature
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, 'f')

    def test_function_key(self):
        protected = {'alg': 'HS256'}
        header = [
            {'protected': protected, 'header': {'kid': 'a'}},
            {'protected': protected, 'header': {'kid': 'b'}},
        ]

        def load_key(header, payload):
            self.assertEqual(payload, b'hello')
            kid = header.get('kid')
            if kid == 'a':
                return 'secret-a'
            return 'secret-b'

        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        s = jws.serialize(header, b'hello', load_key)
        self.assertIsInstance(s, dict)
        self.assertIn('signatures', s)

        data = jws.deserialize(json.dumps(s), load_key)
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header[0]['alg'], 'HS256')
        self.assertNotIn('signature', data)

    def test_fail_deserialize_json(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        self.assertRaises(errors.DecodeError, jws.deserialize_json, None, '')
        self.assertRaises(errors.DecodeError, jws.deserialize_json, '[]', '')
        self.assertRaises(errors.DecodeError, jws.deserialize_json, '{}', '')

        # missing protected
        s = json.dumps({'payload': 'YQ'})
        self.assertRaises(errors.DecodeError, jws.deserialize_json, s, '')

        # missing signature
        s = json.dumps({'payload': 'YQ', 'protected': 'YQ'})
        self.assertRaises(errors.DecodeError, jws.deserialize_json, s, '')

    def test_validate_header(self):
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS, private_headers=[])
        protected = {'alg': 'HS256', 'invalid': 'k'}
        header = {'protected': protected, 'header': {'kid': 'a'}}
        self.assertRaises(
            errors.InvalidHeaderParameterName,
            jws.serialize, header, b'hello', 'secret'
        )
        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS, private_headers=['invalid'])
        s = jws.serialize(header, b'hello', 'secret')
        self.assertIsInstance(s, dict)

        jws = JsonWebSignature(algorithms=JWS_ALGORITHMS)
        s = jws.serialize(header, b'hello', 'secret')
        self.assertIsInstance(s, dict)

    def test_EdDSA_alg(self):
        jws = JsonWebSignature(algorithms=RFC8037_ALGORITHMS)
        private_key = read_file_path('ed25519-pkcs8.pem')
        public_key = read_file_path('ed25519-pub.pem')
        s = jws.serialize({'alg': 'EdDSA'}, 'hello', private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'EdDSA')
