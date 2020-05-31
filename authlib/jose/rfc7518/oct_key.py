from authlib.common.encoding import (
    to_bytes, to_unicode,
    urlsafe_b64encode, urlsafe_b64decode,
)
from authlib.common.security import generate_token
from authlib.jose.rfc7517 import Key


class OctKey(Key):
    """Key class of the ``oct`` key type."""

    kty = 'oct'
    REQUIRED_JSON_FIELDS = ['k']

    def get_op_key(self, key_op):
        self.check_key_op(key_op)
        return self.raw_key

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a key from bytes, string, or dict data."""
        if isinstance(raw, dict):
            cls.check_required_fields(raw)
            payload = raw
            raw_key = urlsafe_b64decode(to_bytes(payload['k']))
        else:
            raw_key = to_bytes(raw)
            k = to_unicode(urlsafe_b64encode(raw_key))
            payload = {'k': k}

        if options is not None:
            payload.update(options)

        obj = cls(payload)
        obj.raw_key = raw_key
        obj.key_type = 'secret'
        return obj

    @classmethod
    def generate_key(cls, key_size=256, options=None, is_private=False):
        """Generate a ``OctKey`` with the given bit size."""
        if not is_private:
            raise ValueError('oct key can not be generated as public')

        if key_size % 8 != 0:
            raise ValueError('Invalid bit size for oct key')

        return cls.import_key(generate_token(key_size // 8), options)
