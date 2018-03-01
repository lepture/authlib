
class JWK(object):
    def __init__(self, algorithms):
        self._algorithms = algorithms

    def loads(self, obj):
        kty = obj['kty']
        alg = self._algorithms[kty]
        return alg.loads(obj)
