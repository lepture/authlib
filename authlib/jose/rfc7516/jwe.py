from authlib.common.encoding import (
    to_bytes, urlsafe_b64encode, json_b64encode
)
from authlib.jose.util import (
    extract_header,
    extract_segment,
    prepare_algorithm_key,
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

    #: Defined available JWS algorithms
    JWE_AVAILABLE_ALGORITHMS = None

    def __init__(self, algorithms, private_headers=None):
        self._alg_algorithms = {}
        self._enc_algorithms = {}
        self._zip_algorithms = {}
        self._private_headers = private_headers

        if algorithms:
            for algorithm in algorithms:
                self.register_algorithm(algorithm)

    def register_algorithm(self, algorithm):
        """Register an algorithm for ``alg`` or ``enc`` or ``zip`` of JWE."""

        if isinstance(algorithm, str) and self.JWE_AVAILABLE_ALGORITHMS:
            algorithm = self.JWE_AVAILABLE_ALGORITHMS.get(algorithm)

        if not algorithm or algorithm.algorithm_type != 'JWE':
            raise ValueError(
                'Invalid algorithm for JWE, {!r}'.format(algorithm))

        if algorithm.algorithm_location == 'alg':
            self._alg_algorithms[algorithm.name] = algorithm
        elif algorithm.algorithm_location == 'enc':
            self._enc_algorithms[algorithm.name] = algorithm
        elif algorithm.algorithm_location == 'zip':
            self._zip_algorithms[algorithm.name] = algorithm

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
        self._pre_validate_header(protected)
        # step 1: Prepare algorithms
        algorithm, enc_alg, key = self._prepare_alg_enc_key(protected, key)
        self._post_validate_header(protected, algorithm)

        # step 2: Generate a random Content Encryption Key (CEK)
        cek = enc_alg.generate_cek()

        # step 3: Encrypt the CEK with the recipient's public key
        ek = algorithm.wrap(cek, protected, key)
        if isinstance(ek, dict):
            # AESGCMKW algorithm contains iv, tag in header
            header = ek.get('header')
            if header:
                protected.update(header)
            ek = ek.get('ek')

        # step 4: Generate a random JWE Initialization Vector
        iv = enc_alg.generate_iv()

        # step 5: Let the Additional Authenticated Data encryption parameter
        # be ASCII(BASE64URL(UTF8(JWE Protected Header)))
        protected_segment = json_b64encode(protected)
        aad = to_bytes(protected_segment, 'ascii')

        # step 6: compress message if required
        msg = self._zip_compress(payload, protected)

        # step 7: perform encryption
        ciphertext, tag = enc_alg.encrypt(msg, aad, iv, cek)
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

        self._pre_validate_header(protected)
        algorithm, enc_alg, key = self._prepare_alg_enc_key(
            protected, key, private=True)
        self._post_validate_header(protected, algorithm)

        cek = algorithm.unwrap(ek, protected, key)
        aad = to_bytes(protected_s, 'ascii')
        msg = enc_alg.decrypt(ciphertext, aad, iv, tag, cek)

        payload = self._zip_decompress(msg, protected)
        if decode:
            payload = decode(payload)
        return {'header': protected, 'payload': payload}

    def _zip_compress(self, s, header):
        s = to_bytes(s)
        if 'zip' in header:
            zip_alg = self._zip_algorithms[header['zip']]
            return zip_alg.compress(s)
        return s

    def _zip_decompress(self, s, header):
        if 'zip' in header:
            zip_alg = self._zip_algorithms[header['zip']]
            return zip_alg.decompress(to_bytes(s))
        return s

    def _prepare_alg_enc_key(self, header, key, private=False):
        algorithm, key = prepare_algorithm_key(
            self._alg_algorithms, header, None, key, private=private)
        enc_alg = self._enc_algorithms[header['enc']]
        return algorithm, enc_alg, key

    def _pre_validate_header(self, header):
        if 'alg' not in header:
            raise MissingAlgorithmError()

        alg = header['alg']
        if alg not in self._alg_algorithms:
            raise UnsupportedAlgorithmError()

        if 'enc' not in header:
            raise MissingEncryptionAlgorithmError()

        enc = header['enc']
        if enc not in self._enc_algorithms:
            raise UnsupportedEncryptionAlgorithmError()

        zip = header.get('zip')
        if zip and zip not in self._zip_algorithms:
            raise UnsupportedCompressionAlgorithmError()

    def _post_validate_header(self, header, alg):
        names = self.REGISTERED_HEADER_PARAMETER_NAMES.copy()
        if self._private_headers:
            names = names.union(self._private_headers)

        if alg.EXTRA_HEADERS:
            names = names.union(alg.EXTRA_HEADERS)

        for k in header:
            if k not in names:
                raise InvalidHeaderParameterName(k)
