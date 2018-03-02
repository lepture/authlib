
class JWK(object):
    def __init__(self, algorithms):
        self._algorithms = algorithms

    def _loads(self, obj):
        kty = obj['kty']
        alg = self._algorithms[kty]
        return alg.loads(obj)

    def loads(self, obj, kid=None):
        if 'kty' in obj:
            if kid and 'kid' in obj and kid != obj['kid']:
                raise ValueError('Invalid JSON Web Key')
            return self._loads(obj)
        if not kid:
            raise ValueError('Invalid JSON Web Key')

        if isinstance(obj, (tuple, list)):
            keys = obj
        elif 'keys' in obj:
            keys = obj['keys']
        else:
            raise ValueError('Invalid JWK set format')

        for key in keys:
            if key['kid'] == kid:
                return self._loads(key)
