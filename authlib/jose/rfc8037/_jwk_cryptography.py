from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from authlib.common.encoding import (
    to_unicode, to_bytes,
    urlsafe_b64decode, urlsafe_b64encode,
)
from ..rfc7517 import JWKAlgorithm
from ._key_cryptography import OKPKey, CURVES_KEYS


class OKPAlgorithm(JWKAlgorithm):
    name = 'OKP'
    key_cls = OKPKey

    def prepare_key(self, raw_data, **params):
        return self.key_cls.from_raw(raw_data, **params)

    def loads(self, key):
        if key.key_data:
            return key

        crv = key.dict_data['crv']
        if crv not in CURVES_KEYS:
            raise ValueError('Unsupported crv for OKP')

        keys = CURVES_KEYS[crv]

        # The parameter "d" MUST be present for private keys
        if 'd' in key.dict_data:
            crv_key = keys[1]
            d_bytes = urlsafe_b64decode(to_bytes(key.dict_data['d']))
            key.key_data = crv_key.from_private_bytes(d_bytes)
        else:
            crv_key = keys[0]
            x_bytes = urlsafe_b64decode(to_bytes(key.dict_data['x']))
            key.key_data = crv_key.from_public_bytes(x_bytes)
        return key

    def dumps(self, key):
        if key.dict_data:
            return key

        crv = key.curve_name
        if not crv:
            raise ValueError('Unsupported key for OKP')

        private_key = key.private_key
        if private_key:
            obj = self.dumps_private_key(private_key)
        else:
            obj = self.dumps_public_key(key.public_key)

        obj['crv'] = crv
        key.dict_data = obj
        return key

    @staticmethod
    def dumps_private_key(key_data):
        obj = OKPAlgorithm.dumps_public_key(key_data.public_key())
        d_bytes = key_data.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )
        obj['d'] = to_unicode(urlsafe_b64encode(d_bytes))
        return obj

    @staticmethod
    def dumps_public_key(key_data):
        x_bytes = key_data.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {'x': to_unicode(urlsafe_b64encode(x_bytes))}
