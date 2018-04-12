import time
from ..rfc7519 import JWT


def sign_jwt_bearer_assertion(
        key, issuer, subject, audience, issued_at=None, expires_at=None,
        claims=None, **kwargs):

    header = kwargs.pop('header', {})
    alg = kwargs.pop('alg', None)
    if alg:
        header['alg'] = alg
    if 'alg' not in header:
        raise ValueError('Missing "alg" in header')

    payload = {'iss': issuer, 'sub': subject, 'aud': audience}
    if not issued_at:
        issued_at = int(time.time())
    if not expires_at:
        expires_at = issued_at + 86400

    payload['iat'] = issued_at
    payload['exp'] = expires_at
    if claims:
        payload.update(claims)

    jwt = JWT()
    return jwt.encode(header, payload, key)
