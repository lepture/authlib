from authlib.oauth2.rfc6749 import AuthorizationCodeMixin as _AuthorizationCodeMixin


class AuthorizationCodeMixin(_AuthorizationCodeMixin):
    def get_nonce(self):
        """Get "nonce" value of the authorization code object."""
        raise NotImplementedError()

    def get_auth_time(self):
        """Get "auth_time" value of the authorization code object."""
        raise NotImplementedError()

    def get_acr(self) -> str:
        """Get the "acr" (Authentication Method Class) value of the authorization code object."""
        raise NotImplementedError()

    def get_amr(self) -> list[str]:
        """Get the "amr" (Authentication Method Reference) value of the authorization code object.

        Have a look at :rfc:`RFC8176 <8176>` to see the full list of registered amr.

            def get_amr(self) -> list[str]:
                return ["pwd", "otp"]

        """
        raise NotImplementedError()
