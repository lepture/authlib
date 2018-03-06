from authlib.specs.rfc7519 import JWT
from authlib.specs.oidc import CodeIDToken
from .base import AppFactory, UserInfo, patch_method, compatible_fetch_user

GOOGLE_API_URL = 'https://www.googleapis.com/'
GOOGLE_TOKEN_URL = GOOGLE_API_URL + 'oauth2/v4/token'
GOOGLE_JWK_URL = GOOGLE_API_URL + 'oauth2/v3/certs'
GOOGLE_AUTH_URL = (
    'https://accounts.google.com/o/oauth2/v2/auth'
    '?access_type=offline'
)
GOOGLE_REVOKE_URL = 'https://accounts.google.com/o/oauth2/revoke'
GOOGLE_JWK_SET = None

GOOGLE_CLAIMS_OPTIONS = {
    "iss": {
        "values": ['https://accounts.google.com', 'accounts.google.com']
    }
}


def parse_openid(client, response, nonce=None):
    jwk_set = _get_google_jwk_set(client)
    id_token = response['id_token']
    claims_request = dict(
        nonce=nonce,
        client_id=client.client_id,
        access_token=response['access_token']
    )
    jwt = JWT()
    claims = jwt.decode(
        id_token, key=jwk_set,
        claims_cls=CodeIDToken,
        claims_options=GOOGLE_CLAIMS_OPTIONS,
        claims_request=claims_request,
    )
    claims.validate(leeway=120)
    return UserInfo(**claims)


def revoke_token(client):
    token = client.get_token()['access_token']
    return client.post(GOOGLE_AUTH_URL, params={'token': token})


def fetch_profile(client):
    resp = client.get('oauth2/v3/userinfo')
    return UserInfo(**resp.json())


def _get_google_jwk_set(client):
    global GOOGLE_JWK_SET
    if not GOOGLE_JWK_SET:
        resp = client.get(GOOGLE_JWK_URL, withhold_token=True)
        GOOGLE_JWK_SET = resp.json()
    return GOOGLE_JWK_SET


google = AppFactory('google', {
    'api_base_url': GOOGLE_API_URL,
    'access_token_url': GOOGLE_TOKEN_URL,
    'authorize_url': GOOGLE_AUTH_URL,
    'client_kwargs': {'scope': 'openid email profile'},
}, "The OAuth app for Google API.")

patch_method(google, revoke_token, 'revoke_token')
patch_method(google, fetch_profile, 'profile')
patch_method(google, parse_openid, 'parse_openid')
compatible_fetch_user(google, fetch_profile)
