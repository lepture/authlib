from authlib.common.urls import add_params_to_qs, add_params_to_uri

__all__ = ['BearToken']


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

    def add_to_body(self, body=None):
        """Add a Bearer Token to the request body.

        access_token=h480djs93hd8
        """
        if body is None:
            body = ''
        return add_params_to_qs(body, [('access_token', self.token)])

    def add_token(self, uri, headers, body, placement='headers'):
        if placement == 'uri':
            uri = self.add_to_uri(uri)
        elif placement == 'headers':
            headers = self.add_to_headers(headers)
        elif placement == 'body':
            body = self.add_to_body(body)
        return uri, headers, body
