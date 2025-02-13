from authlib.oauth2.rfc6749 import AuthorizationCodeMixin as _AuthorizationCodeMixin


class AuthorizationCodeMixin(_AuthorizationCodeMixin):
    def get_nonce(self):
        """Get "nonce" value of the authorization code object."""
        raise NotImplementedError()

    def get_auth_time(self):
        """Get "auth_time" value of the authorization code object."""
        raise NotImplementedError()
