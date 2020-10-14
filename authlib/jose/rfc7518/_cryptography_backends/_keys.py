from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKeyWithSerialization,
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1,
)
from cryptography.hazmat.backends import default_backend
from authlib.jose.rfc7517 import Key, load_pem_key
from authlib.common.encoding import to_bytes
from authlib.common.encoding import base64_to_int, int_to_base64


class RSAKey(Key):
    """Key class of the ``RSA`` key type."""

    kty = 'RSA'
    RAW_KEY_CLS = (RSAPublicKey, RSAPrivateKeyWithSerialization)
    REQUIRED_JSON_FIELDS = ['e', 'n']

    def as_pem(self, is_private=False, password=None):
        """Export key into PEM format bytes.

        :param is_private: export private key or public key
        :param password: encrypt private key with password
        :return: bytes
        """
        return export_key(self, is_private=is_private, password=password)

    @staticmethod
    def dumps_private_key(raw_key):
        numbers = raw_key.private_numbers()
        return {
            'n': int_to_base64(numbers.public_numbers.n),
            'e': int_to_base64(numbers.public_numbers.e),
            'd': int_to_base64(numbers.d),
            'p': int_to_base64(numbers.p),
            'q': int_to_base64(numbers.q),
            'dp': int_to_base64(numbers.dmp1),
            'dq': int_to_base64(numbers.dmq1),
            'qi': int_to_base64(numbers.iqmp)
        }

    @staticmethod
    def dumps_public_key(raw_key):
        numbers = raw_key.public_numbers()
        return {
            'n': int_to_base64(numbers.n),
            'e': int_to_base64(numbers.e)
        }

    @staticmethod
    def loads_private_key(obj):
        if 'oth' in obj:  # pragma: no cover
            # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
            raise ValueError('"oth" is not supported yet')

        props = ['p', 'q', 'dp', 'dq', 'qi']
        props_found = [prop in obj for prop in props]
        any_props_found = any(props_found)

        if any_props_found and not all(props_found):
            raise ValueError(
                'RSA key must include all parameters '
                'if any are present besides d')

        public_numbers = RSAPublicNumbers(
            base64_to_int(obj['e']), base64_to_int(obj['n']))

        if any_props_found:
            numbers = RSAPrivateNumbers(
                d=base64_to_int(obj['d']),
                p=base64_to_int(obj['p']),
                q=base64_to_int(obj['q']),
                dmp1=base64_to_int(obj['dp']),
                dmq1=base64_to_int(obj['dq']),
                iqmp=base64_to_int(obj['qi']),
                public_numbers=public_numbers)
        else:
            d = base64_to_int(obj['d'])
            p, q = rsa_recover_prime_factors(
                public_numbers.n, d, public_numbers.e)
            numbers = RSAPrivateNumbers(
                d=d,
                p=p,
                q=q,
                dmp1=rsa_crt_dmp1(d, p),
                dmq1=rsa_crt_dmq1(d, q),
                iqmp=rsa_crt_iqmp(p, q),
                public_numbers=public_numbers)

        return numbers.private_key(default_backend())

    @staticmethod
    def loads_public_key(obj):
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']),
            base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a key from PEM or dict data."""
        return import_key(
            cls, raw,
            RSAPublicKey, RSAPrivateKeyWithSerialization,
            b'ssh-rsa', options
        )

    @classmethod
    def generate_key(cls, key_size=2048, options=None, is_private=False):
        if key_size < 512:
            raise ValueError('key_size must not be less than 512')
        if key_size % 8 != 0:
            raise ValueError('Invalid key_size for RSAKey')
        raw_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        if not is_private:
            raw_key = raw_key.public_key()
        return cls.import_key(raw_key, options=options)


class ECKey(Key):
    """Key class of the ``EC`` key type."""

    kty = 'EC'
    DSS_CURVES = {
        'P-256': SECP256R1,
        'P-384': SECP384R1,
        'P-521': SECP521R1,
    }
    CURVES_DSS = {
        SECP256R1.name: 'P-256',
        SECP384R1.name: 'P-384',
        SECP521R1.name: 'P-521',
    }
    REQUIRED_JSON_FIELDS = ['crv', 'x', 'y']
    RAW_KEY_CLS = (EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization)

    def as_pem(self, is_private=False, password=None):
        """Export key into PEM format bytes.

        :param is_private: export private key or public key
        :param password: encrypt private key with password
        :return: bytes
        """
        return export_key(self, is_private=is_private, password=password)

    def exchange_shared_key(self, pubkey):
        # # used in ECDHAlgorithm
        if isinstance(self.raw_key, EllipticCurvePrivateKeyWithSerialization):
            return self.raw_key.exchange(ec.ECDH(), pubkey)
        raise ValueError('Invalid key for exchanging shared key')

    @property
    def curve_key_size(self):
        return self.raw_key.curve.key_size

    @classmethod
    def loads_private_key(cls, obj):
        curve = cls.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        private_numbers = EllipticCurvePrivateNumbers(
            base64_to_int(obj['d']),
            public_numbers
        )
        return private_numbers.private_key(default_backend())

    @classmethod
    def loads_public_key(cls, obj):
        curve = cls.DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @classmethod
    def dumps_private_key(cls, raw_key):
        numbers = raw_key.private_numbers()
        return {
            'crv': cls.CURVES_DSS[raw_key.curve.name],
            'x': int_to_base64(numbers.public_numbers.x),
            'y': int_to_base64(numbers.public_numbers.y),
            'd': int_to_base64(numbers.private_value),
        }

    @classmethod
    def dumps_public_key(cls, raw_key):
        numbers = raw_key.public_numbers()
        return {
            'crv': cls.CURVES_DSS[numbers.curve.name],
            'x': int_to_base64(numbers.x),
            'y': int_to_base64(numbers.y)
        }

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a key from PEM or dict data."""
        return import_key(
            cls, raw,
            EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
            b'ecdsa-sha2-', options
        )

    @classmethod
    def generate_key(cls, crv='P-256', options=None, is_private=False):
        if crv not in cls.DSS_CURVES:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        raw_key = ec.generate_private_key(
            curve=cls.DSS_CURVES[crv](),
            backend=default_backend(),
        )
        if not is_private:
            raw_key = raw_key.public_key()
        return cls.import_key(raw_key, options=options)


def import_key(cls, raw, public_key_cls, private_key_cls, ssh_type=None, options=None):
    if isinstance(raw, cls):
        if options is not None:
            raw.update(options)
        return raw

    payload = None
    if isinstance(raw, (public_key_cls, private_key_cls)):
        raw_key = raw
    elif isinstance(raw, dict):
        cls.check_required_fields(raw)
        payload = raw
        if 'd' in payload:
            raw_key = cls.loads_private_key(payload)
        else:
            raw_key = cls.loads_public_key(payload)
    else:
        if options is not None:
            password = options.get('password')
        else:
            password = None
        raw_key = load_pem_key(raw, ssh_type, password=password)

    if isinstance(raw_key, private_key_cls):
        if payload is None:
            payload = cls.dumps_private_key(raw_key)
        key_type = 'private'
    elif isinstance(raw_key, public_key_cls):
        if payload is None:
            payload = cls.dumps_public_key(raw_key)
        key_type = 'public'
    else:
        raise ValueError('Invalid data for importing key')

    obj = cls(payload)
    obj.raw_key = raw_key
    obj.key_type = key_type
    return obj


def export_key(key, encoding=None, is_private=False, password=None):
    if encoding is None or encoding == 'PEM':
        encoding = Encoding.PEM
    elif encoding == 'DER':
        encoding = Encoding.DER
    else:
        raise ValueError('Invalid encoding: {!r}'.format(encoding))

    if is_private:
        if key.key_type == 'private':
            if password is None:
                encryption_algorithm = NoEncryption()
            else:
                encryption_algorithm = BestAvailableEncryption(to_bytes(password))
            return key.raw_key.private_bytes(
                encoding=encoding,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm,
            )
        raise ValueError('This is a public key')

    if key.key_type == 'private':
        raw_key = key.raw_key.public_key()
    else:
        raw_key = key.raw_key

    return raw_key.public_bytes(
        encoding=encoding,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
