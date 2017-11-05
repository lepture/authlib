from .base import AppFactory, User


def dropbox_fetch_user(client):
    resp = client.post('users/get_current_account')
    profile = resp.json()
    uid = profile.get('account_id')
    name = profile['name']['display_name']
    email = profile.get('email')
    username = None
    return User(uid, username=username, name=name, email=email)


dropbox = AppFactory('dropbox', {
    'api_base_url': 'https://www.dropbox.com/2/',
    'access_token_url': 'https://api.dropboxapi.com/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/oauth2/authorize',
    'fetch_user': dropbox_fetch_user,
}, "The OAuth app for Dropbox API.")
