try:
    from authlib.specs.oidc import verify_id_token
except ImportError:
    verify_id_token = None

from .base import AppFactory, User, patch_method

GOOGLE_API_URL = 'https://www.googleapis.com/'
GOOGLE_TOKEN_URL = GOOGLE_API_URL + 'oauth2/v4/token'
GOOGLE_JWK_URL = GOOGLE_API_URL + 'oauth2/v3/certs'
GOOGLE_AUTH_URL = (
    'https://accounts.google.com/o/oauth2/v2/auth'
    '?access_type=offline'
)
GOOGLE_REVOKE_URL = 'https://accounts.google.com/o/oauth2/revoke'
GOOGLE_JWK_SET = None


def google_parse_id_token(client, response, nonce=None):
    global GOOGLE_JWK_SET
    if not GOOGLE_JWK_SET:
        resp = client.get(GOOGLE_JWK_URL, withhold_token=True)
        GOOGLE_JWK_SET = resp.json()['keys']

    client_id = getattr(client, 'client_key', None)
    if not client_id:
        # client can be OAuth2Session
        client_id = client.client_id

    id_token = verify_id_token(
        response, GOOGLE_JWK_SET,
        issuers=('https://accounts.google.com', 'accounts.google.com'),
        client_id=client_id,
        nonce=nonce,
    )
    return _parse_profile(id_token.token)


def google_revoke_token(client):
    token = client.get_token()['access_token']
    return client.post(GOOGLE_AUTH_URL, params={'token': token})


def google_fetch_user(client):
    resp = client.get('oauth2/v3/userinfo')
    profile = resp.json()
    return _parse_profile(profile)


def _parse_profile(profile):
    uid = profile.get('sub')
    name = profile.get('name')
    email = profile.get('email')
    return User(uid, name=name, email=email, data=profile)


google = AppFactory('google', {
    'api_base_url': GOOGLE_API_URL,
    'access_token_url': GOOGLE_TOKEN_URL,
    'authorize_url': GOOGLE_AUTH_URL,
    'client_kwargs': {'scope': 'openid email profile'},
}, "The OAuth app for Google API.")

patch_method(google, google_revoke_token, 'revoke_token')
patch_method(google, google_fetch_user, 'fetch_user')
patch_method(google, google_parse_id_token, 'parse_openid')
