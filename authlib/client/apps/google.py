from .base import AppFactory

GOOGLE_JWK_URL = 'https://www.googleapis.com/oauth2/v3/certs'
GOOGLE_JWK_SET = None

GOOGLE_AUTH_URL = (
    'https://accounts.google.com/o/oauth2/v2/auth'
    '?access_type=offline'
)
GOOGLE_REVOKE_URL = 'https://accounts.google.com/o/oauth2/revoke'


def google_parse_id_token(client, id_token):
    global GOOGLE_JWK_SET
    if not GOOGLE_JWK_SET:
        resp = client.get(GOOGLE_JWK_URL, withhold_token=True)
        GOOGLE_JWK_SET = resp.json()
    # TODO: OpenID Connect
    return


def google_revoke_token(client):
    token = client.get_token()['access_token']
    return client.post(GOOGLE_AUTH_URL, params={'token': token})


google = AppFactory('google', {
    'api_base_url': 'https://www.googleapis.com/',
    'access_token_url': 'https://www.googleapis.com/oauth2/v4/token',
    'authorize_url': GOOGLE_AUTH_URL,
    'client_kwargs': {'scope': ['openid', 'email', 'profile']},
}, "The OAuth app for Google API.")
