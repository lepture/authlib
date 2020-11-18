from authlib.common.encoding import (
    to_bytes, urlsafe_b64encode, json_b64encode
)
from authlib.jose.util import (
    extract_header,
    extract_segment,
)
from authlib.jose.errors import (
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    MissingEncryptionAlgorithmError,
    UnsupportedEncryptionAlgorithmError,
    UnsupportedCompressionAlgorithmError,
    InvalidHeaderParameterName,
)


class JsonWebEncryption(object):
    #: Registered Header Parameter Names defined by Section 4.1
    REGISTERED_HEADER_PARAMETER_NAMES = frozenset([
        'alg', 'enc', 'zip',
        'jku', 'jwk', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit'
    ])

    ALG_REGISTRY = {}
    ENC_REGISTRY = {}
    ZIP_REGISTRY = {}

    def __init__(self, algorithms=None, private_headers=None):
        self._algorithms = algorithms
        self._private_headers = private_headers

    @classmethod
    def register_algorithm(cls, algorithm):
        """Register an algorithm for ``alg`` or ``enc`` or ``zip`` of JWE."""
        if not algorithm or algorithm.algorithm_type != 'JWE':
            raise ValueError(
                'Invalid algorithm for JWE, {!r}'.format(algorithm))

        if algorithm.algorithm_location == 'alg':
            cls.ALG_REGISTRY[algorithm.name] = algorithm
        elif algorithm.algorithm_location == 'enc':
            cls.ENC_REGISTRY[algorithm.name] = algorithm
        elif algorithm.algorithm_location == 'zip':
            cls.ZIP_REGISTRY[algorithm.name] = algorithm

    def serialize_compact(self, protected, payload, key):
        """Generate a JWE Compact Serialization. The JWE Compact Serialization
        represents encrypted content as a compact, URL-safe string.  This
        string is:

            BASE64URL(UTF8(JWE Protected Header)) || '.' ||
            BASE64URL(JWE Encrypted Key) || '.' ||
            BASE64URL(JWE Initialization Vector) || '.' ||
            BASE64URL(JWE Ciphertext) || '.' ||
            BASE64URL(JWE Authentication Tag)

        Only one recipient is supported by the JWE Compact Serialization and
        it provides no syntax to represent JWE Shared Unprotected Header, JWE
        Per-Recipient Unprotected Header, or JWE AAD values.

        :param protected: A dict of protected header
        :param payload: A string/dict of payload
        :param key: Private key used to generate signature
        :return: byte
        """

        # step 1: Prepare algorithms & key
        alg = self.get_header_alg(protected)
        enc = self.get_header_enc(protected)
        zip_alg = self.get_header_zip(protected)
        self._validate_private_headers(protected, alg)

        key = prepare_key(alg, protected, key)

        # self._post_validate_header(protected, algorithm)

        # step 2: Generate a random Content Encryption Key (CEK)
        # use enc_alg.generate_cek() in .wrap method

        # step 3: Encrypt the CEK with the recipient's public key
        wrapped = alg.wrap(enc, protected, key)
        cek = wrapped['cek']
        ek = wrapped['ek']
        if 'header' in wrapped:
            protected.update(wrapped['header'])

        # step 4: Generate a random JWE Initialization Vector
        iv = enc.generate_iv()

        # step 5: Let the Additional Authenticated Data encryption parameter
        # be ASCII(BASE64URL(UTF8(JWE Protected Header)))
        protected_segment = json_b64encode(protected)
        aad = to_bytes(protected_segment, 'ascii')

        # step 6: compress message if required
        if zip_alg:
            msg = zip_alg.compress(to_bytes(payload))
        else:
            msg = to_bytes(payload)

        # step 7: perform encryption
        ciphertext, tag = enc.encrypt(msg, aad, iv, cek)
        return b'.'.join([
            protected_segment,
            urlsafe_b64encode(ek),
            urlsafe_b64encode(iv),
            urlsafe_b64encode(ciphertext),
            urlsafe_b64encode(tag)
        ])

    def deserialize_compact(self, s, key, decode=None):
        """Exact JWS Compact Serialization, and validate with the given key.

        :param s: text of JWS Compact Serialization
        :param key: key used to verify the signature
        :param decode: a function to decode plaintext data
        :return: dict
        """
        try:
            s = to_bytes(s)
            protected_s, ek_s, iv_s, ciphertext_s, tag_s = s.rsplit(b'.')
        except ValueError:
            raise DecodeError('Not enough segments')

        protected = extract_header(protected_s, DecodeError)
        ek = extract_segment(ek_s, DecodeError, 'encryption key')
        iv = extract_segment(iv_s, DecodeError, 'initialization vector')
        ciphertext = extract_segment(ciphertext_s, DecodeError, 'ciphertext')
        tag = extract_segment(tag_s, DecodeError, 'authentication tag')

        alg = self.get_header_alg(protected)
        enc = self.get_header_enc(protected)
        zip_alg = self.get_header_zip(protected)
        self._validate_private_headers(protected, alg)

        key = prepare_key(alg, protected, key)

        cek = alg.unwrap(enc, ek, protected, key)
        aad = to_bytes(protected_s, 'ascii')
        msg = enc.decrypt(ciphertext, aad, iv, tag, cek)

        if zip_alg:
            payload = zip_alg.decompress(to_bytes(msg))
        else:
            payload = msg

        if decode:
            payload = decode(payload)
        return {'header': protected, 'payload': payload}

    def get_header_alg(self, header):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if self._algorithms and alg not in self._algorithms:
            raise UnsupportedAlgorithmError()
        if alg not in self.ALG_REGISTRY:
            raise UnsupportedAlgorithmError()
        return self.ALG_REGISTRY[alg]

    def get_header_enc(self, header):
        if 'enc' not in header:
            raise MissingEncryptionAlgorithmError()
        enc = header['enc']
        if self._algorithms and enc not in self._algorithms:
            raise UnsupportedEncryptionAlgorithmError()
        if enc not in self.ENC_REGISTRY:
            raise UnsupportedEncryptionAlgorithmError()
        return self.ENC_REGISTRY[enc]

    def get_header_zip(self, header):
        if 'zip' in header:
            z = header['zip']
            if self._algorithms and z not in self._algorithms:
                raise UnsupportedCompressionAlgorithmError()
            if z not in self.ZIP_REGISTRY:
                raise UnsupportedCompressionAlgorithmError()
            return self.ZIP_REGISTRY[z]

    def _validate_private_headers(self, header, alg):
        # only validate private headers when developers set
        # private headers explicitly
        if self._private_headers is None:
            return

        names = self.REGISTERED_HEADER_PARAMETER_NAMES.copy()
        names = names.union(self._private_headers)

        if alg.EXTRA_HEADERS:
            names = names.union(alg.EXTRA_HEADERS)

        for k in header:
            if k not in names:
                raise InvalidHeaderParameterName(k)


def prepare_key(alg, header, key):
    if callable(key):
        key = key(header, None)
    elif 'jwk' in header:
        key = header['jwk']
    return alg.prepare_key(key)
