from authlib.common.encoding import json_dumps


class Key(dict):
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

    def get_op_key(self, key_op):
        self.check_key_op(key_op)
        if key_op in self.PUBLIC_KEY_OPS and self.key_type == 'private':
            return self.raw_key.public_key()
        return self.raw_key

    def check_key_op(self, key_op):
        allowed_key_ops = self.get('key_ops')
        if allowed_key_ops is not None and key_op not in allowed_key_ops:
            raise ValueError('Unsupported key_op "{}"'.format(key_op))

        if key_op in self.PRIVATE_KEY_OPS and self.key_type == 'public':
            raise ValueError('Invalid key_op "{}" for public key'.format(key_op))

    def as_dict(self):
        obj = dict(self)
        obj['kty'] = self.kty
        return obj

    def as_json(self):
        obj = self.as_dict()
        return json_dumps(obj)

    def as_pem(self):
        raise RuntimeError('Not supported')

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
    def __init__(self, keys):
        self.keys = keys

    def as_dict(self):
        return {'keys': [k.as_dict() for k in self.keys]}

    def find_by_kid(self, kid):
        for k in self.keys:
            if k.get('kid') == kid:
                return k
        raise ValueError('Invalid JSON Web Key Set')
