from .client import OAuthClient


class AppFactory(object):
    def __init__(self, name, config, doc):
        self.name = name
        self.__doc__ = doc.lstrip()


twitter = AppFactory('twitter', {
    'base_url': 'https://api.twitter.com/1.1/',
    'request_token_url': 'https://api.twitter.com/oauth/request_token',
    'access_token_url': 'https://api.twitter.com/oauth/access_token',
    'authorize_url': 'https://api.twitter.com/oauth/authenticate',
}, "The OAuth app for Twitter API.")


dropbox = AppFactory('dropbox', {
    'base_url': 'https://www.dropbox.com/1/',
    'access_token_url': 'https://api.dropbox.com/1/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/1/oauth2/authorize',
}, "The OAuth app for Dropbox API.")


github = AppFactory('github', {
    'base_url': 'https://api.github.com/',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize',
}, "The OAuth app for GitHub API.")
