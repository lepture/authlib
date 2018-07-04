import unittest
from authlib.specs.rfc7516 import JWE
from authlib.specs.rfc7518 import JWE_ALGORITHMS
from tests.util import read_file_path


class JWETest(unittest.TestCase):
    def test_compact_rsa(self):
        jwe = JWE(algorithms=JWE_ALGORITHMS)
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello',
            read_file_path('rsa_public.pem')
        )
        data = jwe.deserialize_compact(s, read_file_path('rsa_private.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RSA-OAEP')
