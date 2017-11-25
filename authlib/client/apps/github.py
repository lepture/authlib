from .base import AppFactory, User, patch_method


def github_fetch_user(client):
    resp = client.get('user')
    profile = resp.json()
    uid = profile.get('id')
    name = profile.get('name')
    email = profile.get('email')
    return User(uid, name=name, email=email, data=profile)


github = AppFactory('github', {
    'api_base_url': 'https://api.github.com/',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize',
    'client_kwargs': {'scope': 'user:email'},
}, "The OAuth app for GitHub API.")


patch_method(github, github_fetch_user, 'fetch_user')
