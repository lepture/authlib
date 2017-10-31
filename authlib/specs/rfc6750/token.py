from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_qs, add_params_to_uri

__all__ = ['BearerTokenGenerator', 'BearToken']


class BearerTokenGenerator(object):
    def __init__(self, expires_in=3600, validator=None,
                 access_token_generator=None,
                 refresh_token_generator=None):
        self.expires_in = expires_in
        self.validator = validator
        self.access_token = access_token_generator or generate_token
        self.refresh_token = refresh_token_generator or generate_token

    def create_token(self, expires_in=None, include_refresh_token=False):
        if expires_in is None:
            expires_in = self.expires_in

        rv = {
            'access_token': self.access_token(),
            'token_type': 'Bearer',
            'expires_in': expires_in
        }
        if include_refresh_token:
            rv['refresh_token'] = self.refresh_token()
        return rv


class BearToken(object):
    """
    http://tools.ietf.org/html/rfc6750
    """

    def __init__(self, token):
        self.token = token

    def add_to_uri(self, uri):
        """Add a Bearer Token to the request URI.
        Not recommended, use only if client can't use authorization header or body.

        http://www.example.com/path?access_token=h480djs93hd8
        """
        return add_params_to_uri(uri, [('access_token', self.token)])

    def add_to_headers(self, headers=None):
        """Add a Bearer Token to the request URI.
        Recommended method of passing bearer tokens.

        Authorization: Bearer h480djs93hd8
        """
        headers = headers or {}
        headers['Authorization'] = 'Bearer %s' % self.token
        return headers

    def add_to_body(self, body=''):
        """Add a Bearer Token to the request body.

        access_token=h480djs93hd8
        """
        return add_params_to_qs(body, [('access_token', self.token)])

    def add_token(self, uri, headers, body, placement='headers'):
        if placement == 'uri':
            uri = self.add_to_uri(uri)
        elif placement == 'headers':
            headers = self.add_to_headers(headers)
        elif placement == 'body':
            body = self.add_to_body(body)
        return uri, headers, body
