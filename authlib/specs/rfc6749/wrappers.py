import time


class OAuth2Token(dict):
    def __init__(self, params):
        if 'expires_at' in params:
            params['expires_at'] = int(params['expires_at'])
        elif 'expires_in' in params:
            params['expires_at'] = int(time.time()) + \
                                   int(params['expires_in'])
        super(OAuth2Token, self).__init__(params)

    def is_expired(self):
        expires_at = self.get('expires_at')
        if not expires_at:
            return None
        return expires_at < time.time()
