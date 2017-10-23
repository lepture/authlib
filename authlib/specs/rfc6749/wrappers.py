import time


class OAuth2Request(object):
    def __init__(self, method, uri, body=None, headers=None):
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers


class OAuth2Response(object):
    def __init__(self, uri, body, headers=None, status_code=200):
        self.uri = uri
        self.body = body
        self.headers = headers
        self.status_code = status_code


class OAuth2Token(dict):
    def __init__(self, params):
        if 'expires_at' not in params and 'expires_in' in params:
            params['expires_at'] = int(time.time()) + \
                                   int(params['expires_in'])
        super(OAuth2Token, self).__init__(params)
