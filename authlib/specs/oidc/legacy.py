from authlib.specs.rfc7519 import jwt
from authlib.deprecate import deprecate
from .claims import get_claim_cls_by_response_type


def parse_id_token(id_token, key):
    deprecate('"parse_id_token" is deprecated, use JWT instead.', 0.8)
    claims = jwt.decode(id_token, key)
    return claims, claims.header


def verify_id_token(response, key, response_type='code', issuers=None,
                    client_id=None, nonce=None, max_age=None, now=None):
    deprecate('"verify_id_token" is deprecated, use JWT instead.', 0.8)
    if 'id_token' not in response:
        raise ValueError('Invalid OpenID response')

    claims_cls = get_claim_cls_by_response_type(response_type)
    claims_request = {
        'access_token': response.get('access_token'),
        'client_id': client_id,
        'nonce': nonce,
        'max_age': max_age
    }
    claims_options = {
        'iss': {
            'values': issuers,
        }
    }
    claims = jwt.decode(
        response['id_token'], key, claims_cls,
        claims_options=claims_options,
        claims_params=claims_request,
    )
    claims.validate(now=now)
    return claims
