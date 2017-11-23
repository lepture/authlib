import json
from jwt import PyJWS
from jwt.algorithms import RSAAlgorithm


class JWS(PyJWS):
    def parse(self, jws_text, key):
        payload, signing_input, header, signature = self._load(jws_text)

        alg = header['alg']
        kid = header['kid']
        key = _get_key(kid, key)
        try:
            alg_obj = self._algorithms[alg]
            key = alg_obj.prepare_key(key)
            valid = alg_obj.verify(signing_input, key, signature)
        except KeyError:
            # TODO: not supported
            valid = False
        return payload, header, valid


jws = JWS()


def _get_key(kid, key):
    if isinstance(key, dict):
        if key['kid'] == kid:
            return _jwk_to_key(key)

    if isinstance(key, (list, tuple)):
        for jwk in key:
            if jwk['kid'] == kid:
                return _jwk_to_key(jwk)

    return key


def _jwk_to_key(jwk):
    if isinstance(jwk, dict):
        # TODO: send a PR to PyJWT
        jwk = json.dumps(jwk)
    return RSAAlgorithm.from_jwk(jwk)
