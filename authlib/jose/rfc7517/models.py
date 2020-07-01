import hashlib
from collections import OrderedDict
from authlib.common.encoding import (
    json_dumps,
    to_bytes,
    to_unicode,
    urlsafe_b64encode,
)
from ..errors import InvalidUseError


class Key(dict):
    """This is the base class for a JSON Web Key."""
    kty = '_'

    ALLOWED_PARAMS = [
        'use', 'key_ops', 'alg', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256'
    ]

    PRIVATE_KEY_OPS = [
        'sign', 'decrypt', 'unwrapKey',
    ]
    PUBLIC_KEY_OPS = [
        'verify', 'encrypt', 'wrapKey',
    ]

    REQUIRED_JSON_FIELDS = []
    RAW_KEY_CLS = bytes

    def __init__(self, payload):
        super(Key, self).__init__(payload)

        self.key_type = 'secret'
        self.raw_key = None

    def get_op_key(self, operation):
        """Get the raw key for the given key_op. This method will also
        check if the given key_op is supported by this key.

        :param operation: key operation value, such as "sign", "encrypt".
        :return: raw key
        """
        self.check_key_op(operation)
        if operation in self.PUBLIC_KEY_OPS:
            return self.get_public_key()
        return self.get_private_key()

    def get_public_key(self):
        if self.key_type == 'private':
            return self.raw_key.public_key()
        return self.raw_key

    def get_private_key(self):
        if self.key_type == 'private':
            return self.raw_key

    def check_key_op(self, operation):
        """Check if the given key_op is supported by this key.

        :param operation: key operation value, such as "sign", "encrypt".
        :raise: ValueError
        """
        key_ops = self.get('key_ops')
        if key_ops is not None and operation not in key_ops:
            raise ValueError('Unsupported key_op "{}"'.format(operation))

        if operation in self.PRIVATE_KEY_OPS and self.key_type == 'public':
            raise ValueError('Invalid key_op "{}" for public key'.format(operation))

        use = self.get('use')
        if use:
            if operation in ['sign', 'verify']:
                if use != 'sig':
                    raise InvalidUseError()
            elif operation in ['decrypt', 'encrypt', 'wrapKey', 'unwrapKey']:
                if use != 'enc':
                    raise InvalidUseError()

    def as_key(self):
        """Represent this key as raw key."""
        return self.raw_key

    def as_dict(self, add_kid=False):
        """Represent this key as a dict of the JSON Web Key."""
        obj = dict(self)
        obj['kty'] = self.kty
        if add_kid and 'kid' not in obj:
            obj['kid'] = self.thumbprint()
        return obj

    def as_json(self):
        """Represent this key as a JSON string."""
        obj = self.as_dict()
        return json_dumps(obj)

    def as_pem(self):
        """Represent this key as string in PEM format."""
        raise RuntimeError('Not supported')

    def thumbprint(self):
        """Implementation of RFC7638 JSON Web Key (JWK) Thumbprint."""
        fields = list(self.REQUIRED_JSON_FIELDS)
        fields.append('kty')
        fields.sort()
        data = OrderedDict()

        obj = self.as_dict()
        for k in fields:
            data[k] = obj[k]

        json_data = json_dumps(data)
        digest_data = hashlib.sha256(to_bytes(json_data)).digest()
        return to_unicode(urlsafe_b64encode(digest_data))

    @classmethod
    def check_required_fields(cls, data):
        for k in cls.REQUIRED_JSON_FIELDS:
            if k not in data:
                raise ValueError('Missing required field: "{}"'.format(k))

    @classmethod
    def generate_key(cls, crv_or_size, options=None, is_private=False):
        raise NotImplementedError()

    @classmethod
    def import_key(cls, raw, options=None):
        raise NotImplementedError()


class KeySet(object):
    """This class represents a JSON Web Key Set."""

    def __init__(self, keys):
        self.keys = keys

    def as_dict(self):
        """Represent this key as a dict of the JSON Web Key Set."""
        return {'keys': [k.as_dict(True) for k in self.keys]}

    def as_json(self):
        """Represent this key set as a JSON string."""
        obj = self.as_dict()
        return json_dumps(obj)

    def find_by_kid(self, kid):
        """Find the key matches the given kid value.

        :param kid: A string of kid
        :return: Key instance
        :raise: ValueError
        """
        for k in self.keys:
            if k.get('kid') == kid:
                return k
        raise ValueError('Invalid JSON Web Key Set')
