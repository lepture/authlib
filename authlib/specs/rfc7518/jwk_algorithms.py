# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518
    ~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""

from authlib.specs.rfc7517 import JWKAlgorithm
from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode,
)
from ._backends import JWK_ALGORITHMS


class OCTAlgorithm(JWKAlgorithm):
    def prepare_key(self, key):
        return to_bytes(key)

    def loads(self, obj):
        return urlsafe_b64decode(to_bytes(obj['k']))

    def dumps(self, key):
        return {
            'k': to_unicode(urlsafe_b64encode(key)),
            'kty': 'oct'
        }


JWK_ALGORITHMS['oct'] = OCTAlgorithm()
