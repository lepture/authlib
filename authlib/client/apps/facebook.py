import json
from authlib.common.urls import urlparse
from authlib.common.encoding import to_bytes
from .base import AppFactory


def facebook_compliance_fix(session):
    """Compliance fix for Facebook."""

    def _compliance_fix(r):
        # if Facebook claims to be sending us json, let's trust them.
        content_type = r.headers.get('content-type', {})
        if 'application/json' in content_type:
            return r

        # Facebook returns a content-type of text/plain when sending their
        # x-www-form-urlencoded responses, along with a 200. If not, let's
        # assume we're getting JSON and bail on the fix.
        if 'text/plain' in content_type and r.status_code == 200:
            token = dict(urlparse.parse_qsl(r.text, keep_blank_values=True))
        else:
            return r

        expires = token.pop('expires', None)
        if expires is not None:
            token['expires_in'] = expires
        token['token_type'] = 'Bearer'
        r._content = to_bytes(json.dumps(token))
        return r

    session.register_compliance_hook('access_token_response', _compliance_fix)
    return session


def facebook_fetch_user(client):
    pass


facebook = AppFactory('facebook', {
    'api_base_url': 'https://graph.facebook.com/v2.10',
    'access_token_url': 'https://graph.facebook.com/v2.10/oauth/access_token',
    'access_token_params': {'method': 'GET'},
    'authorize_url': 'https://www.facebook.com/v2.10/dialog/oauth',
    'client_kwargs': {'scope': 'email'},
    'fetch_user': facebook_fetch_user,
    'compliance_fix': facebook_compliance_fix,
}, "The OAuth app for Facebook API.")
