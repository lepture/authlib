# -*- coding: utf-8 -*-
"""
    authlib.jose.rfc7518.jwk_algorithms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""

from authlib.jose.rfc7517 import JWKAlgorithm
from authlib.common.encoding import (
    to_bytes, to_unicode, byte_type,
    urlsafe_b64encode, urlsafe_b64decode,
)
from .oct_key import OctKey
from ._backends import JWK_ALGORITHMS as _ALGORITHMS


class OCTAlgorithm(JWKAlgorithm):
    name = 'oct'

    def check_key_data(self, key_data):
        return isinstance(key_data, (byte_type, OctKey))

    def prepare_key(self, raw_data, **params):
        return OctKey.from_raw(raw_data, **params)

    def loads(self, key):
        if not key.key_data:
            k = to_bytes(key.dict_data['k'])
            key.key_data = urlsafe_b64decode(k)
        return key

    def dumps(self, key):
        if not key.dict_data:
            k = to_unicode(urlsafe_b64encode(key.dict_data))
            key.dict_data = {'k': k}
        return key


JWK_ALGORITHMS = _ALGORITHMS + [OCTAlgorithm()]
