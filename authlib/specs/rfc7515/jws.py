import json
from authlib.common.encoding import (
    to_bytes,
    to_unicode,
    urlsafe_b64encode,
    json_b64encode
)
from .errors import (
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    BadSignatureError,
    InvalidHeaderParameterName,
)
from .util import (
    prepare_algorithm_key,
    extract_header,
    extract_segment,
)


class JWSAlgorithm(object):
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """
    def prepare_private_key(self, key):
        """Prepare key for sign signature."""
        raise NotImplementedError

    def prepare_public_key(self, key):
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

    #: Registered Header Parameter Names defined by `Section 4.1`_
    REGISTERED_HEADER_PARAMETER_NAMES = frozenset([
        'alg', 'jku', 'jwk', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit'
    ])

    def __init__(self, algorithms, private_headers=None):
        self._algorithms = algorithms
        self._private_headers = private_headers

    def deserialize_compact(self, s, key):
        """Exact JWS Compact Serialization, and validate with the given key.
        If key is not provided, the returned dict will contain the signature,
        and signing input values. Via `Section 7.1`_.

        :param s: text of JWS Compact Serialization
        :param key: key used to verify the signature
        :return: dict
        :raise: BadSignatureError

        .. _`Section 7.1`: https://tools.ietf.org/html/rfc7515#section-7.1
        """
        try:
            s = to_bytes(s)
            signing_input, signature_segment = s.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise DecodeError('Not enough segments')

        # extract header, payload, signature
        header = _extract_header(header_segment)
        payload = _extract_payload(payload_segment)
        signature = _extract_signature(signature_segment)

        self._validate_header(header)
        if not key:
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'signing_input': signing_input,
            }

        algorithm, key = prepare_algorithm_key(
            self._algorithms, header, payload, key)
        if algorithm.verify(signing_input, key, signature):
            return {'header': header, 'payload': payload}
        raise BadSignatureError()

    def deserialize_json(self, s, key):
        """Exact JWS JSON Serialization, and validate with the given key.
        If key is not provided, it will return a dict without signature
        verification. Header will still be validated. Via `Section 7.2`_.

        :param s: text of JWS JSON Serialization
        :param key: key used to verify the signature
        :return: dict
        :raise: BadSignatureError

        .. _`Section 7.2`: https://tools.ietf.org/html/rfc7515#section-7.2
        """
        s = _ensure_dict(s)

        payload_segment = s.get('payload')
        if not payload_segment:
            raise DecodeError('Missing "payload" value')

        payload_segment = to_bytes(payload_segment)
        payload = _extract_payload(payload_segment)
        if key:
            if 'signatures' not in s:
                # flattened JSON JWS
                header = self._validate_json_jws(
                    payload_segment, payload, s, key)
                return {'header': header, 'payload': payload}

            header = [
                self._validate_json_jws(
                    payload_segment, payload, segments, key)
                for segments in s['signatures']
            ]
            return {'header': header, 'payload': payload}

        if 'signatures' in s:
            for segments in s['signatures']:
                self._validate_json_jws(
                    payload_segment, payload, segments, None)
        else:
            self._validate_json_jws(payload_segment, payload, s, None)
        return s

    def deserialize(self, s, key):
        """Deserialize JWS Serialization, both compact and JSON format.
        It will automatically deserialize depending on the given JWS.

        :param s: text of JWS Compact/JSON Serialization
        :param key: key used to verify the signature
        :return: dict
        :raise: BadSignatureError

        If key is not provided, it will still deserialize the serialization
        without verification.
        """
        if isinstance(s, dict):
            return self.deserialize_json(s, key)
        s = to_bytes(s)
        if s.startswith(b'{'):
            return self.deserialize_json(s, key)
        return self.deserialize_compact(s, key)

    def serialize_compact(self, header, payload, key):
        """Generate a JWS Compact Serialization. The JWS Compact Serialization
        represents digitally signed or MACed content as a compact, URL-safe
        string, per `Section 7.1`_.

        .. code-block:: text

            BASE64URL(UTF8(JWS Protected Header)) || '.' ||
            BASE64URL(JWS Payload) || '.' ||
            BASE64URL(JWS Signature)

        :param header: A dict of header
        :param payload: A string/dict of payload
        :param key: Private key used to generate signature
        :return: byte
        """
        protected, payload_segment, signature = self._sign_signature(
            header, payload, key)
        return b'.'.join([protected, payload_segment, signature])

    def serialize_json(self, header, payload, key):
        """Generate a JWS JSON Serialization. The JWS JSON Serialization
        represents digitally signed or MACed content as a JSON object,
        per `Section 7.2`_.

        :param header: A dict/list of header
        :param payload: A string/dict of payload
        :param key: Private key used to generate signature
        :return: dict

        Example header of JWS JSON Serialization::

            {
                "protected: {"alg": "HS256"},
                "header": {"kid": "jose"}
            }

        Pass a dict to generate flattened JSON Serialization, pass a list of
        header dict to generate standard JSON Serialization.
        """
        payload_segment = json_b64encode(payload)

        def _sign(h):
            protected, _, signature = self._sign_signature(
                h['protected'], payload, key, payload_segment)
            rv = {
                'protected': to_unicode(protected),
                'signature': to_unicode(signature)
            }
            if 'header' in header:
                rv['header'] = h['header']
            return rv

        if isinstance(header, dict):
            data = _sign(header)
            data['payload'] = to_unicode(payload_segment)
            return data

        signatures = [_sign(h) for h in header]
        return {
            'payload': to_unicode(payload_segment),
            'signatures': signatures
        }

    def serialize(self, header, payload, key):
        """Generate a JWS Serialization. It will automatically generate a
        Compact or JSON Serialization depending on the given header. If a
        header is in a JSON header format, it will call
        :meth:`serialize_json`, otherwise it will call
        :meth:`serialize_compact`.

        :param header: A dict/list of header
        :param payload: A string/dict of payload
        :param key: Private key used to generate signature
        :return: byte/dict
        """
        if isinstance(header, (list, tuple)):
            return self.serialize_json(header, payload, key)
        if 'protected' in header:
            return self.serialize_json(header, payload, key)
        return self.serialize_compact(header, payload, key)

    def _validate_header(self, header):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if alg not in self._algorithms:
            raise UnsupportedAlgorithmError()

        names = self.REGISTERED_HEADER_PARAMETER_NAMES.copy()
        if self._private_headers:
            names = names.union(self._private_headers)

        for k in header:
            if k not in names:
                raise InvalidHeaderParameterName(k)

    def _validate_json_jws(self, payload_segment, payload, header_obj, key):
        protected = header_obj.get('protected')
        if not protected:
            raise DecodeError('Missing "protected" value')

        signature_segment = header_obj.get('signature')
        if not signature_segment:
            raise DecodeError('Missing "signature" value')

        protected = to_bytes(protected)
        header = _extract_header(protected)
        pub_header = header_obj.get('header')
        if pub_header:
            if not isinstance(pub_header, dict):
                raise DecodeError('Invalid "header" value')
            header.update(pub_header)

        self._validate_header(header)
        if not key:
            return header

        algorithm, key = prepare_algorithm_key(
            self._algorithms, header, payload, key)
        signing_input = b'.'.join([protected, payload_segment])
        signature = _extract_signature(to_bytes(signature_segment))
        if algorithm.verify(signing_input, key, signature):
            return header

        raise BadSignatureError()

    def _sign_signature(self, header, payload, key, payload_segment=None):
        self._validate_header(header)
        algorithm, key = prepare_algorithm_key(
            self._algorithms, header, payload, key, private=True)

        protected = json_b64encode(header)
        if payload_segment is None:
            payload_segment = json_b64encode(payload)
        signing_input = b'.'.join([protected, payload_segment])
        signature = urlsafe_b64encode(algorithm.sign(signing_input, key))
        return protected, payload_segment, signature


def _extract_header(header_segment):
    return extract_header(header_segment, DecodeError)


def _extract_signature(signature_segment):
    return extract_segment(signature_segment, DecodeError, 'signature')


def _extract_payload(payload_segment):
    return extract_segment(payload_segment, DecodeError, 'payload')


def _ensure_dict(s):
    if not isinstance(s, dict):
        try:
            s = json.loads(to_unicode(s))
        except (ValueError, TypeError):
            raise DecodeError('Invalid JWS')

    if not isinstance(s, dict):
        raise DecodeError('Invalid JWS')

    return s
