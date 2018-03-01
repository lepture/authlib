# -*- coding: utf-8 -*-
"""
    authlib.specs.rfc7518.jws
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Cryptographic Algorithms for Keys per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc7518#section-6
"""

import json
from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode
)


class RSAAlgorithm(object):
    @staticmethod
    def loads(s):
        pass

    @staticmethod
    def dumps(s):
        pass


class OCTAlgorithm(object):
    @staticmethod
    def loads(obj):
        return urlsafe_b64decode(to_bytes(obj['k']))

    @staticmethod
    def dumps(s):
        return json.dumps({
            'k': to_unicode(urlsafe_b64encode(to_bytes(s))),
            'kty': 'oct'
        })


JWK_ALGORITHMS = {
    'oct': OCTAlgorithm,
    'RSA': RSAAlgorithm,
}
