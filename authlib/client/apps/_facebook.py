from authlib.specs.oidc import UserInfo
from .base import AppFactory, patch_method


def fetch_profile(client):
    resp = client.get(
        'me?fields=id,name,'
        'first_name,middle_name,last_name,'
        'email,website,gender,locale'
    )
    data = resp.json()
    params = {
        'sub': str(data['id']),
        'name': data['name'],
        'given_name': data.get('first_name'),
        'family_name': data.get('last_name'),
        'middle_name': data.get('middle_name'),
        'email': data.get('email'),
        'website': data.get('website'),
        'gender': data.get('gender'),
        'locale': data.get('locale')
    }
    return UserInfo(params)


facebook = AppFactory('facebook', {
    'api_base_url': 'https://graph.facebook.com/v2.11',
    'access_token_url': 'https://graph.facebook.com/v2.11/oauth/access_token',
    'access_token_params': {'method': 'GET'},
    'authorize_url': 'https://www.facebook.com/v2.11/dialog/oauth',
    'client_kwargs': {'scope': 'email public_profile'},
}, "The OAuth app for Facebook API.")

patch_method(facebook, fetch_profile, 'profile')
