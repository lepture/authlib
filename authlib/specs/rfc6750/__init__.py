from authlib.common.security import generate_token

__all__ = ['BearerToken']


class BearerToken(object):
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
