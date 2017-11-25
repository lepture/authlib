from .base import AppFactory, User, patch_method


def twitter_fetch_user(client):
    url = 'account/verify_credentials.json'
    params = {
        'skip_status': True,
        'include_email': True
    }
    resp = client.get(url, params=params)
    profile = resp.json()
    uid = profile.get('id')
    name = profile.get('name')
    email = profile.get('email')
    return User(uid, name=name, email=email, data=profile)


twitter = AppFactory('twitter', {
    'api_base_url': 'https://api.twitter.com/1.1/',
    'request_token_url': 'https://api.twitter.com/oauth/request_token',
    'access_token_url': 'https://api.twitter.com/oauth/access_token',
    'authorize_url': 'https://api.twitter.com/oauth/authenticate',
}, "The OAuth app for Twitter API.")


patch_method(twitter, twitter_fetch_user, 'fetch_user')
