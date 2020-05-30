from authlib.common.encoding import text_types, json_loads
from .rfc7517 import KeySet
from .rfc7518 import (
    OctKey,
    RSAKey,
    ECKey,
    load_pem_key,
)
from .rfc8037 import OKPKey


class JsonWebKey(object):
    JWK_KEY_CLS = {
        OctKey.kty: OctKey,
        RSAKey.kty: RSAKey,
        ECKey.kty: ECKey,
        OKPKey.kty: OKPKey,
    }

    @classmethod
    def generate_key(cls, kty, crv_or_size, options=None, is_private=False):
        """Generate a Key with the given key type, curve name or bit size.

        :param kty: string of ``oct``, ``RSA``, ``EC``, ``OKP``
        :param crv_or_size: curve name or bit size
        :param options: a dict of other options for Key
        :param is_private: create a private key or public key
        :return: Key instance
        """
        key_cls = cls.JWK_KEY_CLS[kty]
        return key_cls.generate_key(crv_or_size, options, is_private)

    @classmethod
    def import_key(cls, raw, options=None):
        """Import a Key from bytes, string, PEM or dict.

        :return: Key instance
        """
        kty = None
        if options is not None:
            kty = options.get('kty')

        if kty is None and isinstance(raw, dict):
            kty = raw.get('kty')

        if kty is None:
            raw_key = load_pem_key(raw)
            for _kty in cls.JWK_KEY_CLS:
                key_cls = cls.JWK_KEY_CLS[_kty]
                if isinstance(raw_key, key_cls.RAW_KEY_CLS):
                    return key_cls.import_key(raw_key, options)

        key_cls = cls.JWK_KEY_CLS[kty]
        return key_cls.import_key(raw, options)

    @classmethod
    def import_key_set(cls, raw):
        """Import KeySet from string, dict or a list of keys.

        :return: KeySet instance
        """
        if isinstance(raw, text_types) and \
                raw.startswith('{') and raw.endswith('}'):
            raw = json_loads(raw)
            keys = raw.get('keys')
        elif isinstance(raw, dict) and 'keys' in raw:
            keys = raw.get('keys')
        elif isinstance(raw, (tuple, list)):
            keys = raw
        else:
            return None

        return KeySet([cls.import_key(k) for k in keys])


def loads(obj, kid=None):
    # TODO: deprecate
    key_set = JsonWebKey.import_key_set(obj)
    if key_set:
        return key_set.find_by_kid(kid)
    return JsonWebKey.import_key(obj)


def dumps(key, kty=None, **params):
    # TODO: deprecate
    if kty:
        params['kty'] = kty

    key = JsonWebKey.import_key(key, params)
    data = key.as_dict()
    return data
