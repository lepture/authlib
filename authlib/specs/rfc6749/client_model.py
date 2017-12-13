
class OAuth2Client(object):
    @classmethod
    def get_by_client_id(cls, client_id):
        raise NotImplementedError()

    def get_default_redirect_uri(self):
        raise NotImplementedError()

    def check_redirect_uri(self, redirect_uri):
        """Validate redirect_uri parameter in Authorization Endpoints."""
        raise NotImplementedError()

    def check_client_type(self, client_type):
        """ OAuth defines two client types, based on their ability to
        authenticate securely with the authorization server.

        confidential
            Clients capable of maintaining the confidentiality of their
            credentials (e.g., client implemented on a secure server with
            restricted access to the client credentials), or capable of secure
            client authentication using other means.

        public
            Clients incapable of maintaining the confidentiality of their
            credentials (e.g., clients executing on the device used by the
            resource owner, such as an installed native application or a web
            browser-based application), and incapable of secure client
            authentication via any other means.
        """
        raise NotImplementedError()

    def check_response_type(self, response_type):
        raise NotImplementedError()

    def check_grant_type(self, grant_type):
        raise NotImplementedError()

    def check_requested_scopes(self, scopes):
        raise NotImplementedError()
