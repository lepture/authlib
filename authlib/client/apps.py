import json
from ..common.urls import urlparse
from ..common.encoding import to_bytes

__all__ = ['twitter', 'dropbox', 'github', 'facebook']


class AppFactory(object):
    def __init__(self, name, config, doc, compliance_fix=None):
        self.name = name
        self.config = config
        self.compliance_fix = compliance_fix
        self.oauth = None
        self._client = None
        self.__doc__ = doc.lstrip()

    def register_to(self, oauth):
        kwargs = {}
        if self.compliance_fix:
            kwargs['compliance_fix'] = self.compliance_fix

        kwargs.update(self.config)
        oauth.register(self.name, **kwargs)
        self.oauth = oauth

    @property
    def client(self):
        if self._client:
            return self._client
        if self.oauth:
            self._client = self.oauth.create_client(self.name)
            return self._client
        raise RuntimeError('App not `register_to` any oauth registry')

    def get(self, url, **kwargs):
        return self.client.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self.client.post(url, **kwargs)

    def put(self, url, **kwargs):
        return self.client.put(url, **kwargs)

    def delete(self, url, **kwargs):
        return self.client.delete(url, **kwargs)


twitter = AppFactory('twitter', {
    'api_base_url': 'https://api.twitter.com/1.1/',
    'request_token_url': 'https://api.twitter.com/oauth/request_token',
    'access_token_url': 'https://api.twitter.com/oauth/access_token',
    'authorize_url': 'https://api.twitter.com/oauth/authenticate',
}, "The OAuth app for Twitter API.")


dropbox = AppFactory('dropbox', {
    'api_base_url': 'https://www.dropbox.com/1/',
    'access_token_url': 'https://api.dropbox.com/1/oauth2/token',
    'authorize_url': 'https://www.dropbox.com/1/oauth2/authorize',
}, "The OAuth app for Dropbox API.")


github = AppFactory('github', {
    'api_base_url': 'https://api.github.com/',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize',
    'client_kwargs': {'scope': 'user:email'},
}, "The OAuth app for GitHub API.")


def facebook_compliance_fix(session):

    def _compliance_fix(r):
        # if Facebook claims to be sending us json, let's trust them.
        content_type = r.headers.get('content-type', {})
        if 'application/json' in content_type:
            return r

        # Facebook returns a content-type of text/plain when sending their
        # x-www-form-urlencoded responses, along with a 200. If not, let's
        # assume we're getting JSON and bail on the fix.
        if 'text/plain' in content_type and r.status_code == 200:
            token = dict(urlparse.parse_qsl(r.text, keep_blank_values=True))
        else:
            return r

        expires = token.pop('expires', None)
        if expires is not None:
            token['expires_in'] = expires
        token['token_type'] = 'Bearer'
        r._content = to_bytes(json.dumps(token))
        return r

    session.register_compliance_hook('access_token_response', _compliance_fix)
    return session


facebook = AppFactory('facebook', {
    'api_base_url': 'https://graph.facebook.com/v2.10',
    'access_token_url': 'https://graph.facebook.com/v2.10/oauth/access_token',
    'access_token_params': {'method': 'GET'},
    'authorize_url': 'https://www.facebook.com/v2.10/dialog/oauth',
    'client_kwargs': {'scope': 'email'},
}, "The OAuth app for Facebook API.", facebook_compliance_fix)


google = AppFactory('google', {
    'api_base_url': 'https://www.googleapis.com/oauth2/v1/',
    'access_token_url': 'https://accounts.google.com/o/oauth2/token',
    'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
    'client_kwargs': {'scope': 'email'},
}, "The OAuth app for Google API.")
