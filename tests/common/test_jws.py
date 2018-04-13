import unittest
import json
from authlib.specs.rfc7515 import JWS
from authlib.specs.rfc7515 import errors
from authlib.specs.rfc7518 import JWS_ALGORITHMS
from tests.util import read_file_path


class JWSTest(unittest.TestCase):
    def test_invalid_input(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
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
        jws = JWS(algorithms=JWS_ALGORITHMS)
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
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = 'eyJhbGciOiJIUzI1NiJ9.YQ.YQ'
        self.assertRaises(errors.BadSignatureError, jws.deserialize, s, 'k')

    def test_compact_jws(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = jws.serialize({'alg': 'HS256'}, 'hello', 'secret')
        data = jws.deserialize(s, 'secret')
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'HS256')
        self.assertNotIn('signature', data)

        # no key
        data = jws.deserialize(s, None)
        self.assertIn('signature', data)
        self.assertIn('signing_input', data)

    def test_compact_rsa(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = jws.serialize(
            {'alg': 'RS256'}, 'hello',
            read_file_path('rsa_private.pem')
        )
        data = jws.deserialize(s, read_file_path('rsa_public.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RS256')

    def test_flattened_json_jws(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        protected = {'alg': 'HS256'}
        header = {'protected': protected, 'header': {'kid': 'a'}}
        s = jws.serialize(header, 'hello', 'secret')
        self.assertIsInstance(s, dict)

        data = jws.deserialize(s, 'secret')
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'HS256')
        self.assertNotIn('protected', data)

        data = jws.deserialize(s, None)
        self.assertIn('protected', data)

    def test_nested_json_jws(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
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

        data = jws.deserialize(s, None)
        self.assertIn('signatures', data)

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

        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = jws.serialize(header, b'hello', load_key)
        self.assertIsInstance(s, dict)
        self.assertIn('signatures', s)

        data = jws.deserialize(json.dumps(s), load_key)
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header[0]['alg'], 'HS256')
        self.assertNotIn('signature', data)

    def test_fail_deserialize_json(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
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
        jws = JWS(algorithms=JWS_ALGORITHMS)
        protected = {'alg': 'HS256', 'invalid': 'k'}
        header = {'protected': protected, 'header': {'kid': 'a'}}
        self.assertRaises(
            errors.InvalidHeaderParameterName,
            jws.serialize, header, b'hello', 'secret'
        )
        jws = JWS(algorithms=JWS_ALGORITHMS, private_headers=['invalid'])
        s = jws.serialize(header, b'hello', 'secret')
        self.assertIsInstance(s, dict)
