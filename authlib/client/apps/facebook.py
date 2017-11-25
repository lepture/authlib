from .base import AppFactory, User, patch_method


def facebook_fetch_user(client):
    resp = client.get('me?fields=id,name,email,website')
    profile = resp.json()
    uid = profile.get('id')
    name = profile.get('name')
    email = profile.get('email')
    return User(uid, name=name, email=email, data=profile)


facebook = AppFactory('facebook', {
    'api_base_url': 'https://graph.facebook.com/v2.11',
    'access_token_url': 'https://graph.facebook.com/v2.11/oauth/access_token',
    'access_token_params': {'method': 'GET'},
    'authorize_url': 'https://www.facebook.com/v2.11/dialog/oauth',
    'client_kwargs': {'scope': 'email public_profile'},
}, "The OAuth app for Facebook API.")

patch_method(facebook, facebook_fetch_user, 'fetch_user')
