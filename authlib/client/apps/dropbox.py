from .base import AppFactory, User, patch_method


def dropbox_fetch_user(client):
    resp = client.post('users/get_current_account')
    profile = resp.json()
    uid = profile.get('account_id')
    name = profile['name']['display_name']
    email = profile.get('email')
    return User(uid, name=name, email=email, data=profile)


dropbox = AppFactory('dropbox', {
    'api_base_url': 'https://www.dropbox.com/2/',
    'access_token_url': 'https://api.dropboxapi.com/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/oauth2/authorize',
}, "The OAuth app for Dropbox API.")

patch_method(dropbox, dropbox_fetch_user, 'fetch_user')
