from .key import Key


class JWKAlgorithm(object):
    name = None
    description = None
    algorithm_type = 'JWK'
    algorithm_location = 'kty'
    key_cls = Key

    """Interface for JWK algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWK with this base implementation.
    """
    def check_key_data(self, key_data):
        if isinstance(key_data, self.key_cls):
            return True
        if isinstance(key_data, self.key_cls.private_key_cls):
            return True
        return isinstance(key_data, self.key_cls.public_key_cls)

    def prepare_key(self, raw_data, **params):
        """Prepare key before dumping it into JWK."""
        raise NotImplementedError()

    def loads(self, obj):
        """Load JWK dict object into a public/private key."""
        raise NotImplementedError()

    def dumps(self, key):
        """Dump a public/private key into JWK dict object."""
        raise NotImplementedError()


class JsonWebKey(object):
    #: Defined available JWK algorithms
    JWK_AVAILABLE_ALGORITHMS = None

    def __init__(self, algorithms):
        self._algorithms = {}

        if isinstance(algorithms, list):
            for algorithm in algorithms:
                self.register_algorithm(algorithm)

    def register_algorithm(self, algorithm):
        if isinstance(algorithm, str) and self.JWK_AVAILABLE_ALGORITHMS:
            algorithm = self.JWK_AVAILABLE_ALGORITHMS.get(algorithm)

        if not algorithm or algorithm.algorithm_type != 'JWK':
            raise ValueError(
                'Invalid algorithm for JWK, {!r}'.format(algorithm))

        self._algorithms[algorithm.name] = algorithm

    def prepare(self, raw_key, kty=None, **params):
        if kty is None:
            alg = self._find_key_alg(raw_key)
        else:
            alg = self._algorithms[kty]

        if not alg:
            raise ValueError('Unsupported key for JWK')

        key = alg.prepare_key(raw_key, **params)
        return alg, key

    def loads(self, obj, kid=None):
        """Loads JSON Web Key object into a public/private key.

        :param obj: A JWK (or JWK set) format dict
        :param kid: kid of a JWK set
        :return: key
        """
        key = self._load_jwk_set(obj, kid)
        if key is not None:
            return key

        alg, key = self.prepare(obj)
        alg.loads(key)
        if kid and kid != key.kid:
            raise ValueError('Key "kid" not matching')
        return key

    def dumps(self, key, kty=None, **params):
        """Generate JWK format for the given public/private key.

        :param key: A public/private key
        :param kty: key type of the key
        :param params: Other parameters
        :return: JWK dict
        """
        alg, key = self.prepare(key, kty, **params)
        alg.dumps(key)
        return key.as_dict()

    def __call__(self, raw_data, kty=None, **params):
        alg, key = self.prepare(raw_data, kty, **params)
        alg.dumps(key)
        alg.loads(key)
        return key

    def _load_jwk_set(self, obj, kid):
        if isinstance(obj, (tuple, list)):
            keys = obj
        elif 'keys' in obj:
            keys = obj['keys']
        else:
            return None

        for raw_key in keys:
            if raw_key.get('kid') == kid:
                alg, key = self.prepare(raw_key)
                alg.loads(key)
                return key

        raise ValueError('Invalid JWK kid')

    def _find_key_alg(self, key):
        if isinstance(key, dict):
            if 'kty' not in key:
                raise ValueError('Invalid key: %r'.format(key))
            kty = key['kty']
            return self._algorithms[kty]

        for kty in self._algorithms:
            alg = self._algorithms[kty]
            if alg.check_key_data(key):
                return alg
