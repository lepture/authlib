import binascii
import json
from collections import Mapping
from authlib.common.encoding import (
    to_bytes, urlsafe_b64encode, urlsafe_b64decode
)
from .errors import (
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    BadSignatureError,
)


class JWSAlgorithm(object):
    def prepare_sign_key(self, key):
        raise NotImplementedError

    def prepare_verify_key(self, key):
        raise NotImplementedError

    def sign(self, msg, key):
        raise NotImplementedError

    def verify(self, msg, key, sig):
        raise NotImplementedError


class JWS(object):
    def __init__(self, algorithms, load_key=None):
        self._algorithms = algorithms
        self.load_key = load_key

    def verify(self, s, key):
        header, payload, signing_input, signature = extract(s)

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

        if self.load_key:
            key = self.load_key(key, header)

        algorithm = self._algorithms[alg]
        key = algorithm.prepare_verify_key(key)
        verified = algorithm.verify(signing_input, key, signature)

        # Note that the payload can be any content and need not
        # be a representation of a JSON object
        return header, payload, verified

    def decode(self, s, key):
        header, payload, verified = self.verify(s, key)
        if verified:
            return header, payload
        raise BadSignatureError()

    def encode(self, header, payload, key):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

        algorithm = self._algorithms[alg]

        if self.load_key:
            key = self.load_key(key, header)

        key = algorithm.prepare_sign_key(key)

        header = json.dumps(header, separators=(',', ':'))
        if isinstance(payload, Mapping):
            payload = json.dumps(payload, separators=(',', ':'))

        segments = [
            urlsafe_b64encode(to_bytes(header)),
            urlsafe_b64encode(to_bytes(payload)),
        ]
        signing_input = b'.'.join(segments)
        signature = algorithm.sign(signing_input, key)
        return b'.'.join([signing_input, signature])


def extract(s):
    try:
        s = to_bytes(s)
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
