import time
from authlib.jose import jwt


def sign_jwt_bearer_assertion(
        key, issuer, audience, subject=None, issued_at=None,
        expires_at=None, claims=None, header=None, **kwargs):

    if header is None:
        header = {}
    alg = kwargs.pop('alg', None)
    if alg:
        header['alg'] = alg
    if 'alg' not in header:
        raise ValueError('Missing "alg" in header')

    payload = {'iss': issuer, 'aud': audience}

    # subject is not required in Google service
    if subject:
        payload['sub'] = subject

    if not issued_at:
        issued_at = int(time.time())

    expires_in = kwargs.pop('expires_in', 3600)
    if not expires_at:
        expires_at = issued_at + expires_in

    payload['iat'] = issued_at
    payload['exp'] = expires_at

    if claims:
        payload.update(claims)

    return jwt.encode(header, payload, key)
