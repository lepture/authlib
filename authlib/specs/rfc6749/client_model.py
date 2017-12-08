
class OAuth2Client(object):
    @classmethod
    def get_by_client_id(cls, client_id):
        raise NotImplementedError()

    def get_default_redirect_uri(self):
        raise NotImplementedError()

    def check_redirect_uri(self, redirect_uri):
        raise NotImplementedError()

    def check_client_type(self, client_type):
        raise NotImplementedError()

    def check_response_type(self, response_type):
        raise NotImplementedError()

    def check_grant_type(self, grant_type):
        raise NotImplementedError()

    def check_requested_scopes(self, scopes):
        raise NotImplementedError()
