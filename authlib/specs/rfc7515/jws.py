import binascii
import json
from collections import Mapping
from authlib.common.encoding import urlsafe_b64decode
from .errors import (
    DecodeError,
    UnsupportedAlgorithmError,
    BadSignatureError,
)


class JWS(object):
    def __init__(self, algorithms):
        self._algorithms = algorithms
        self._load_verify_key = None

    def verify(self, s, key):
        header, payload, signing_input, signature = extract(s)

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

        if self._load_verify_key:
            key = self._load_verify_key(key, header)

        algorithm = self._algorithms[alg]
        key = algorithm.prepare_verify_key(key)
        verified = algorithm.verify(signing_input, key, signature)

        # Note that the payload can be any content and need not
        # be a representation of a JSON object
        return header, payload, verified

    def decode(self, s, key):
        header, payload, verified = self.verify(s, key)
        if verified:
            return payload
        raise BadSignatureError()


def extract(s):
    try:
        signing_input, signature_segment = s.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise DecodeError('Not enough segments')

    try:
        header_data = urlsafe_b64decode(header_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid header padding')

    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise DecodeError('Invalid header string: {}'.format(e))

    if not isinstance(header, Mapping):
        raise DecodeError('Header must be a json object')

    if 'alg' not in header:
        raise DecodeError('Missing "alg" in header')

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid payload padding')

    try:
        signature = urlsafe_b64decode(signature_segment)
    except (TypeError, binascii.Error):
        raise DecodeError('Invalid crypto padding')

    return header, payload, signing_input, signature
