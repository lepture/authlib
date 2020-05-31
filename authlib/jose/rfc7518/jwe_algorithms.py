import zlib
from ._backends import JWE_ALG_ALGORITHMS as _JWE_ALG_ALGORITHMS, JWE_ENC_ALGORITHMS
from .oct_key import OctKey
from ..rfc7516 import JWEAlgorithm, JWEZipAlgorithm


__all__ = [
    'JWE_ALG_ALGORITHMS', 'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS', 'JWE_ALGORITHMS',
]


class DirectAlgorithm(JWEAlgorithm):
    name = 'dir'
    description = 'Direct use of a shared symmetric key'

    def prepare_key(self, raw_data):
        return OctKey.import_key(raw_data)

    def wrap(self, enc_alg, headers, key):
        cek = key.get_op_key('encrypt')
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return {'ek': b'', 'cek': cek}

    def unwrap(self, enc_alg, ek, headers, key):
        cek = key.get_op_key('decrypt')
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class DeflateZipAlgorithm(JWEZipAlgorithm):
    name = 'DEF'
    description = 'DEFLATE'

    def compress(self, s):
        """Compress bytes data with DEFLATE algorithm."""
        data = zlib.compress(s)
        # drop gzip headers and tail
        return data[2:-4]

    def decompress(self, s):
        """Decompress DEFLATE bytes data."""
        return zlib.decompress(s, -zlib.MAX_WBITS)


JWE_ALG_ALGORITHMS = [DirectAlgorithm()] + _JWE_ALG_ALGORITHMS
JWE_ZIP_ALGORITHMS = [DeflateZipAlgorithm()]
JWE_ALGORITHMS = JWE_ALG_ALGORITHMS + JWE_ENC_ALGORITHMS + JWE_ZIP_ALGORITHMS
