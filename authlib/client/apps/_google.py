try:
    from authlib.specs.oidc import verify_id_token
except ImportError:  # pragma: no cover
    verify_id_token = None

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

# the second one doesn't respect spec
GOOGLE_ISSUES = ('https://accounts.google.com', 'accounts.google.com')


def parse_id_token(client, response, nonce=None):
    jwk_set = _get_google_jwk_set(client)

    id_token = verify_id_token(
        response, jwk_set,
        issuers=GOOGLE_ISSUES,
        client_id=client.client_id,
        nonce=nonce,
    )
    return UserInfo(**id_token.token)


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
        GOOGLE_JWK_SET = resp.json()['keys']
    return GOOGLE_JWK_SET


google = AppFactory('google', {
    'api_base_url': GOOGLE_API_URL,
    'access_token_url': GOOGLE_TOKEN_URL,
    'authorize_url': GOOGLE_AUTH_URL,
    'client_kwargs': {'scope': 'openid email profile'},
}, "The OAuth app for Google API.")

patch_method(google, revoke_token, 'revoke_token')
patch_method(google, fetch_profile, 'profile')
patch_method(google, parse_id_token, 'parse_openid')
compatible_fetch_user(google, fetch_profile)
