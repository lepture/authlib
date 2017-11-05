from .base import AppFactory, User


def twitter_fetch_user(client):
    url = 'account/verify_credentials.json'
    params = {
        'skip_status': True,
        'include_email': True
    }
    resp = client.get(url, params)
    profile = resp.json()
    uid = profile.get('id')
    username = profile.get('screen_name')
    name = profile.get('name')
    email = profile.get('email')
    return User(uid, username=username, name=name, email=email)


twitter = AppFactory('twitter', {
    'api_base_url': 'https://api.twitter.com/1.1/',
    'request_token_url': 'https://api.twitter.com/oauth/request_token',
    'access_token_url': 'https://api.twitter.com/oauth/access_token',
    'authorize_url': 'https://api.twitter.com/oauth/authenticate',
    'fetch_user': twitter_fetch_user,
}, "The OAuth app for Twitter API.")
