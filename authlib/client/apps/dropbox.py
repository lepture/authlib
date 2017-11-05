from .base import AppFactory


dropbox = AppFactory('dropbox', {
    'api_base_url': 'https://www.dropbox.com/1/',
    'access_token_url': 'https://api.dropbox.com/1/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/1/oauth2/authorize',
}, "The OAuth app for Dropbox API.")
