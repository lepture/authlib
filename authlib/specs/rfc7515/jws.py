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
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """
    def prepare_sign_key(self, key):
        """Prepare key for sign signature."""
        raise NotImplementedError

    def prepare_verify_key(self, key):
        """Prepare key for verify signature."""
        raise NotImplementedError

    def sign(self, msg, key):
        """Sign the text msg with a private/sign key.

        :param msg: message bytes to be signed
        :param key: private key to sign the message
        :return: bytes
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """Verify the signature of text msg with a public/verify key.

        :param msg: message bytes to be signed
        :param key: public key to verify the signature
        :param sig: result signature to be compared
        :return: boolean
        """
        raise NotImplementedError


class JWS(object):
    def __init__(self, algorithms):
        self._algorithms = algorithms

    def extract(self, s):
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

        try:
            payload = urlsafe_b64decode(payload_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid payload padding')

        try:
            signature = urlsafe_b64decode(signature_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid crypto padding')

        self._validate_header(header)
        return header, payload, signing_input, signature

    def _validate_header(self, header):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

    def _prepare_algorithm_key(self, header, payload, key):
        algorithm = self._algorithms[header['alg']]
        if callable(key):
            key = key(header, payload)
        return algorithm, key

    def verify(self, s, key):
        """Extract and verify the JSON web signature.

        :param s: text of JWS
        :param key: key used to verify the signature
        :returns: (header, payload, verified)
        """
        header, payload, signing_input, signature = self.extract(s)
        algorithm, key = self._prepare_algorithm_key(header, payload, key)
        key = algorithm.prepare_verify_key(key)
        verified = algorithm.verify(signing_input, key, signature)

        # Note that the payload can be any content and need not
        # be a representation of a JSON object
        return header, payload, verified

    def decode(self, s, key):
        """Decode the JWS with the given key. This is similar with
        :meth:`verify`, except that it will raise BadSignatureError when
        signature doesn't match.

        :param s: text of JWS
        :param key: key used to verify the signature
        :return: (header, payload)
        :raise: BadSignatureError
        """
        header, payload, verified = self.verify(s, key)
        if verified:
            return header, payload
        raise BadSignatureError()

    def encode(self, header, payload, key):
        """Encode a JWS with the given header, payload and key.

        :param header: A dict of JWS header
        :param payload: text/dict to be encoded
        :param key: key used to sign the signature
        :return: JWS text
        """
        self._validate_header(header)
        algorithm, key = self._prepare_algorithm_key(header, payload, key)
        key = algorithm.prepare_sign_key(key)
        header = json.dumps(header, separators=(',', ':'))
        if isinstance(payload, Mapping):
            payload = json.dumps(payload, separators=(',', ':'))

        segments = [
            urlsafe_b64encode(to_bytes(header)),
            urlsafe_b64encode(to_bytes(payload)),
        ]
        signing_input = b'.'.join(segments)
        signature = urlsafe_b64encode(algorithm.sign(signing_input, key))
        return b'.'.join([signing_input, signature])
