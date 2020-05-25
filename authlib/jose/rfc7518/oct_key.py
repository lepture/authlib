from authlib.common.encoding import to_bytes
from authlib.jose.rfc7517 import Key


class OctKey(Key):
    kty = 'oct'
    required_key_fields = ['k']

    def get_supported_key_ops(self):
        return ['sign', 'verify', 'wrapKey', 'unwrapKey']

    def get_operation_key(self, key_op):
        self.check_operation(key_op)
        return self.key_data

    @classmethod
    def from_raw(cls, raw_data, **params):
        if isinstance(raw_data, cls):
            raw_data.update(**params)
            return raw_data

        key = cls(raw_data, **params)
        if isinstance(raw_data, dict):
            key.check_key_fields(raw_data)
            key.dict_data = raw_data
        else:
            key.key_data = to_bytes(raw_data)
        return key
