from typing import Optional

from authlib.common.urls import add_params_to_uri


class IssuerParameter:
    def __call__(self, grant):
        grant.register_hook(
            "after_authorization_response",
            self.add_issuer_parameter,
        )

    def add_issuer_parameter(self, hook_type: str, response):
        if self.get_issuer():
            # RFC9207 §2
            # In authorization responses to the client, including error responses,
            # an authorization server supporting this specification MUST indicate
            # its identity by including the iss parameter in the response.

            new_location = add_params_to_uri(
                response.location, {"iss": self.get_issuer()}
            )
            response.location = new_location

    def get_issuer(self) -> Optional[str]:
        """Return the issuer URL.
        Developers MAY implement this method if they want to support :rfc:`RFC9207 <9207>`::

            def get_issuer(self) -> str:
                return "https://auth.example.org"
        """
        return None
