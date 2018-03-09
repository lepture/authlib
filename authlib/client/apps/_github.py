from authlib.specs.oidc import UserInfo
from .base import AppFactory, patch_method


def fetch_profile(client):
    resp = client.get('user')
    data = resp.json()
    params = {
        'sub': str(data['id']),
        'name': data['name'],
        'email': data.get('email'),
        'preferred_username': data['login'],
        'profile': data['html_url'],
        'picture': data['avatar_url'],
        'website': data.get('blog'),
    }
    # updated_at = data.get('updated_at')
    # TODO: params['updated_at'] = updated_at
    return UserInfo(params)


github = AppFactory('github', {
    'api_base_url': 'https://api.github.com/',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize',
    'client_kwargs': {'scope': 'user:email'},
}, "The OAuth app for GitHub API.")


patch_method(github, fetch_profile, 'profile')
