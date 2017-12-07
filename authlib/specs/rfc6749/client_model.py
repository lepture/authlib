
class OAuth2Client(object):
    def check_redirect_uri(self, redirect_uri):
        raise NotImplementedError()

    def check_client_type(self, client_type):
        raise NotImplementedError()

    def check_response_type(self, response_type):
        raise NotImplementedError()

    def check_requested_scopes(self, scopes):
        raise NotImplementedError()

    def parse_authorization_code(self, code):
        raise NotImplementedError()

    def create_authorization_code(self, user, redirect_uri):
        raise NotImplementedError()

    def destroy_authorization_code(self, code):
        raise NotImplementedError()

    def create_access_token(self, user):
        raise NotImplementedError()
