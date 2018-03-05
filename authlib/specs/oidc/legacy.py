from authlib.specs.rfc7519 import JWT
from authlib.deprecate import deprecate
from .claims import get_claim_cls_by_response_type


def parse_id_token(id_token, key):
    deprecate('"parse_id_token" is deprecated, use JWT instead.', 0.8)
    jwt = JWT()
    claims = jwt.decode(id_token, key)
    return claims, claims.header


def verify_id_token(response, key, response_type='code', issuers=None,
                    client_id=None, nonce=None, max_age=None):
    deprecate('"verify_id_token" is deprecated, use JWT instead.', 0.8)
    if 'id_token' not in response:
        raise ValueError('Invalid OpenID response')

    claims_cls = get_claim_cls_by_response_type(response_type)
    claims_options = {
        'iss': issuers,
        'aud': client_id,
        'nonce': nonce,
        'max_age': max_age
    }
    jwt = JWT(claims_options=claims_options)
    claims = jwt.decode(response['id_token'], key, claims_cls)
    claims.validate()
    return claims
