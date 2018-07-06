import zlib
from ._backends import JWE_ALG_ALGORITHMS, JWE_ENC_ALGORITHMS
from ..rfc7516 import JWEZipAlgorithm


__all__ = [
    'JWE_ALG_ALGORITHMS', 'JWE_ENC_ALGORITHMS',
    'JWE_ZIP_ALGORITHMS', 'JWE_ALGORITHMS',
]


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


JWE_ZIP_ALGORITHMS = [DeflateZipAlgorithm()]
JWE_ALGORITHMS = JWE_ALG_ALGORITHMS + JWE_ENC_ALGORITHMS + JWE_ZIP_ALGORITHMS
