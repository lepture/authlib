import zlib
from ._backends import JWE_ALG_ALGORITHMS, JWE_ENC_ALGORITHMS
from ..rfc7516 import JWEZipAlgorithm


__all__ = ['JWE_ALGORITHMS']


class DeflateZipAlgorithm(JWEZipAlgorithm):
    name = 'DEF',
    description = 'DEFLATED'

    def compress(self, b):
        return zlib.compress(b)[2:-4]

    def decompress(self, s):
        return zlib.decompress(s, -zlib.MAX_WBITS)


JWE_ZIP_ALGORITHMS = [DeflateZipAlgorithm]
JWE_ALGORITHMS = JWE_ALG_ALGORITHMS + JWE_ENC_ALGORITHMS + JWE_ZIP_ALGORITHMS
