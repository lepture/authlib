
from authlib.specs.rfc6749 import (
    AuthorizationCodeMixin as _AuthorizationCodeMixin
)


class AuthorizationCodeMixin(_AuthorizationCodeMixin):
    def get_nonce(self):
        raise NotImplementedError()

    def get_auth_time(self):
        raise NotImplementedError()
