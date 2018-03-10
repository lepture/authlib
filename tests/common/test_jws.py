import unittest
from authlib.specs.rfc7515 import JWS
from authlib.specs.rfc7515 import errors
from authlib.specs.rfc7518 import JWS_ALGORITHMS
from tests.util import get_rsa_private_key, get_rsa_public_key


class JWSTest(unittest.TestCase):
    def test_invalid_input(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        self.assertRaises(errors.DecodeError, jws.decode, 'a', 'k')
        self.assertRaises(errors.DecodeError, jws.decode, 'a.b.c', 'k')
        self.assertRaises(errors.DecodeError, jws.decode, 'YQ.YQ.YQ', 'k')  # a
        self.assertRaises(errors.DecodeError, jws.decode, 'W10.a.YQ', 'k')  # []
        self.assertRaises(errors.DecodeError, jws.decode, 'e30.a.YQ', 'k')  # {}
        self.assertRaises(
            errors.DecodeError, jws.decode, 'eyJhbGciOiJzIn0.a.YQ', 'k')
        self.assertRaises(
            errors.DecodeError, jws.decode, 'eyJhbGciOiJzIn0.YQ.a', 'k')

    def test_invalid_alg(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.decode, 'eyJhbGciOiJzIn0.YQ.YQ', 'k')
        self.assertRaises(
            errors.MissingAlgorithmError,
            jws.encode, {}, '', 'k'
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jws.encode, {'alg': 's'}, '', 'k'
        )

    def test_bad_signature(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = 'eyJhbGciOiJIUzI1NiJ9.YQ.YQ'
        self.assertRaises(errors.BadSignatureError, jws.decode, s, 'k')

    def test_success_encode_decode(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = jws.encode({'alg': 'HS256'}, 'hello', 'secret')
        header, payload = jws.decode(s, 'secret')
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'HS256')

    def test_rsa_encode_decode(self):
        jws = JWS(algorithms=JWS_ALGORITHMS)
        s = jws.encode({'alg': 'RS256'}, 'hello', get_rsa_private_key())
        header, payload = jws.decode(s, get_rsa_public_key())
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RS256')

