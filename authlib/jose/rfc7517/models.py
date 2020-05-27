from authlib.common.encoding import json_dumps


class Key(dict):
    kty = '_'

    ALLOWED_PARAMS = [
        'use', 'key_ops', 'alg', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256'
    ]
    ALLOWED_KEY_OPS = [
        'sign', 'verify',
        'wrapKey', 'unwrapKey',
    ]
    REQUIRED_JSON_FIELDS = []
    RAW_KEY_CLS = bytes

    def __init__(self, payload):
        # only import allowed parameters
        kwargs = {k: payload[k] for k in payload if k in self.ALLOWED_PARAMS}
        super(Key, self).__init__(kwargs)

        self.key_type = 'secret'
        self.raw_key = None

    def get_op_key(self, key_op):
        raise NotImplementedError()

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
