from ._backends import EC_TYPES, RSA_TYPES


class JWKAlgorithm(object):
    name = None
    description = None
    algorithm_type = 'JWK'
    algorithm_location = 'kty'

    """Interface for JWK algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWK with this base implementation.
    """
    def prepare_key(self, key):
        """Prepare key before dumping it into JWK."""
        raise NotImplementedError

    def loads(self, obj):
        """Load JWK dict object into a public/private key."""
        raise NotImplementedError

    def dumps(self, key):
        """Dump a public/private key into JWK dict object."""
        raise NotImplementedError


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

    def _load_obj(self, obj):
        kty = obj['kty']
        alg = self._algorithms[kty]
        return alg.loads(obj)

    def _load_jwk_set(self, obj, kid):
        if isinstance(obj, (tuple, list)):
            keys = obj
        elif 'keys' in obj:
            keys = obj['keys']
        else:
            raise ValueError('Invalid JWK set format')

        for key in keys:
            if key.get('kid') == kid:
                return self._load_obj(key)
        raise ValueError('Invalid JWK kid')

    def loads(self, obj, kid=None):
        """Loads JSON Web Key object into a public/private key.

        :param obj: A JWK (or JWK set) format dict
        :param kid: kid of a JWK set
        :return: key
        """
        if 'kty' in obj:
            if kid and 'kid' in obj and kid != obj['kid']:
                raise ValueError('Invalid JSON Web Key')
            return self._load_obj(obj)
        return self._load_jwk_set(obj, kid)

    def dumps(self, key, kty=None, **params):
        """Generate JWK format for the given public/private key.

        :param key: A public/private key
        :param kty: key type of the key
        :param params: Other parameters
        :return: JWK dict
        """
        if kty is None:
            if isinstance(key, EC_TYPES):
                kty = 'EC'
            elif isinstance(key, RSA_TYPES):
                kty = 'RSA'
            else:
                kty = 'oct'

        alg = self._algorithms[kty]
        obj = alg.dumps(alg.prepare_key(key))

        if params:
            _add_other_params(obj, params)

        return obj


def _add_other_params(obj, params):
    # https://tools.ietf.org/html/rfc7517#section-4
    others = [
        'use', 'key_ops', 'alg', 'kid',
        'x5u', 'x5c', 'x5t', 'x5t#S256'
    ]
    for k in others:
        value = params.get(k)
        if value:
            obj[k] = value
