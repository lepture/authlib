from authlib.common.encoding import json_dumps


class Key(object):
    kty = None
    required_key_fields = []
    private_key_cls = bytes
    public_key_cls = bytes

    ALLOWED_PARAMS = [
        'use', 'key_ops', 'alg', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256'
    ]

    #: https://tools.ietf.org/html/rfc7517#section-4.2
    ALLOWED_USE = ['sig', 'enc']

    #: https://tools.ietf.org/html/rfc7517#section-4.3
    ALLOWED_KEY_OPS = [
        'sign', 'verify',
        'encrypt', 'decrypt',
        'wrapKey', 'unwrapKey',
        'deriveKey', 'deriveBits',
    ]

    def __init__(self, raw_data, **params):
        self.raw_data = raw_data
        self._params = params
        self.key_data = None
        self.dict_data = {}

    def as_key(self):
        return self.key_data

    def as_dict(self):
        obj = dict(self.dict_data)
        obj['kty'] = self.kty
        for k in self.ALLOWED_PARAMS:
            if k in self._params:
                obj[k] = self._params[k]
        return obj

    def as_json(self):
        return json_dumps(self.as_dict())

    def update(self, **params):
        self._params.update(params)

    def get_operation_key(self, key_op):
        self.check_operation(key_op)
        if key_op in ['sign', 'decrypt', 'unwrapKey', 'deriveKey']:
            return self.private_key
        else:
            return self.public_key

    def check_key_fields(self, obj):
        for k in self.required_key_fields:
            if k not in obj:
                raise ValueError('Missing "{}" in "{}"'.format(k, obj))

    def check_operation(self, key_op):
        supported_key_ops = self.get_supported_key_ops()
        is_supported = key_op in supported_key_ops
        if is_supported and self.key_ops:
            is_supported = key_op in self.key_ops

        if not is_supported:
            raise ValueError('Operation "{}" is not supported'.format(key_op))
        return True

    @property
    def public_key(self):
        return None

    @property
    def private_key(self):
        return None

    @property
    def kid(self):
        return self.dict_data.get('kid') or self._params.get('kid')

    @property
    def alg(self):
        return self.dict_data.get('alg') or self._params.get('alg')

    @property
    def use(self):
        return self.dict_data.get('use') or self._params.get('use')

    @property
    def key_ops(self):
        return self.dict_data.get('key_ops') or self._params.get('key_ops')

    @property
    def x5u(self):
        return self.dict_data.get('x5u') or self._params.get('x5u')

    @property
    def x5c(self):
        return self.dict_data.get('x5c') or self._params.get('x5c')

    @property
    def x5t(self):
        return self.dict_data.get('x5t') or self._params.get('x5t')

    @property
    def x5t_s256(self):
        return self.dict_data.get('x5t#S256') or self._params.get('x5t#S256')

    def get_supported_key_ops(self):
        raise NotImplementedError()

    @classmethod
    def from_raw(cls, raw_data, **params):
        raise NotImplementedError()
