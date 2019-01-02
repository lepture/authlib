# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7518.jwk_algorithms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""

from authlib.jose.rfc7517 import JWKAlgorithm
from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode,
)
from ._backends import JWK_ALGORITHMS as _ALGORITHMS


class OCTAlgorithm(JWKAlgorithm):
    name = 'oct'

    def prepare_key(self, key):
        return to_bytes(key)

    def loads(self, obj):
        return urlsafe_b64decode(to_bytes(obj['k']))

    def dumps(self, key):
        return {
            'k': to_unicode(urlsafe_b64encode(key)),
            'kty': 'oct'
        }


JWK_ALGORITHMS = _ALGORITHMS + [OCTAlgorithm()]
