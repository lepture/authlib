

class BearerToken(object):
    DEFAULT_EXPIRES_IN = 3600

    def __init__(self, access_token_generator,
                 refresh_token_generator=None,
                 expires_generator=None):
        self.access_token_generator = access_token_generator
        self.refresh_token_generator = refresh_token_generator
        self.expires_generator = expires_generator

    def __call__(self, client, grant_type, expires_in=None,
                 scope=None, include_refresh_token=True):

        access_token = self.access_token_generator()

        if expires_in is None:
            if self.expires_generator is None:
                expires_in = self.DEFAULT_EXPIRES_IN
            elif callable(self.expires_generator):
                expires_in = self.expires_generator(client, grant_type)
            elif isinstance(self.expires_generator, int):
                expires_in = self.expires_generator
            else:
                expires_in = self.DEFAULT_EXPIRES_IN

        token = {
            'token_type': 'Bearer',
            'access_token': access_token,
            'expires_in': expires_in
        }
        if include_refresh_token and self.refresh_token_generator:
            token['refresh_token'] = self.refresh_token_generator()
        if scope:
            token['scope'] = scope
        return token
