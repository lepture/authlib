class JsonWebKey(object):
    #: Defined available JWK Key class
    JWK_KEY_CLS = {}

    def __init__(self, key_types=None):
        all_key_types = [k for k in self.JWK_KEY_CLS.keys() if k != '_']
        if key_types is None:
            self._allowed_key_types = all_key_types
        else:
            for k in key_types:
                if k not in all_key_types:
                    raise ValueError('Key type "{}" is not supported'.format(k))
            self._allowed_key_types = key_types

    def generate_key(self, kty, crv_or_size, options=None, is_private=False):
        if kty not in self._allowed_key_types:
            raise ValueError('Key type "{}" is not supported'.format(kty))

        key_cls = self.JWK_KEY_CLS[kty]
        return key_cls.generate_key(crv_or_size, options, is_private)

    def import_key(self, raw, options=None):
        kty = None
        if options is not None:
            kty = options.get('kty')

        if kty is None and isinstance(raw, dict):
            kty = raw.get('kty')

        if kty is None:
            key_cls = self.JWK_KEY_CLS['_']
            raw_key = key_cls.import_key(raw, options)
            for _jkc in self.JWK_KEY_CLS:
                if isinstance(raw_key, _jkc.RAW_KEY_CLS):
                    return _jkc.import_key(raw_key, options)

        if kty not in self._allowed_key_types:
            raise ValueError('Key type "{}" is not supported'.format(kty))
        key_cls = self.JWK_KEY_CLS[kty]
        return key_cls.import_key(raw, options)

    def loads(self, obj, kid=None):
        """Loads JSON Web Key object into a public/private key.

        :param obj: A JWK (or JWK set) format dict
        :param kid: kid of a JWK set
        :return: key
        """
        # TODO: deprecate
        if kid:
            key = self.import_key(obj, {'kid': kid})
        else:
            key = self.import_key(obj)
        return key

    def dumps(self, key, kty=None, **params):
        """Generate JWK format for the given public/private key.

        :param key: A public/private key
        :param kty: key type of the key
        :param params: Other parameters
        :return: JWK dict
        """
        # TODO: deprecate
        if kty:
            params['kty'] = kty
        k = self.import_key(key, params)
        return k.as_dict()
