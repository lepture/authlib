from .base import AppFactory, UserInfo, patch_method, compatible_fetch_user


def fetch_profile(client):
    resp = client.post('users/get_current_account')
    data = resp.json()
    name_info = data['name']
    params = {
        'sub': data['account_id'],
        'name': name_info.get('display_name'),
        'given_name': name_info.get('given_name'),
        'family_name': name_info.get('surname'),
        'nickname': name_info.get('familiar_name'),
        'email': data.get('email'),
        'email_verified': data.get('email_verified'),
        'locale': data.get('locale'),
        'picture': data.get('profile_photo_url'),
    }
    return UserInfo(**params)


dropbox = AppFactory('dropbox', {
    'api_base_url': 'https://www.dropbox.com/2/',
    'access_token_url': 'https://api.dropboxapi.com/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/oauth2/authorize',
}, "The OAuth app for Dropbox API.")

patch_method(dropbox, fetch_profile, 'profile')
compatible_fetch_user(dropbox, fetch_profile)
