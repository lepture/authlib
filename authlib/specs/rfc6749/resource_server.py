from .util import scope_to_list


class ResourceServer(object):
    def authenticate_token(self, token_string, token_type):
        """
        :param token_string: A string to represent the access_token.
        :param token_type: The token_type of the access_token.
        :return: token
        """
        raise NotImplementedError()

    def get_token_user(self, token):
        raise NotImplementedError()

    def get_token_scope(self, token):
        raise NotImplementedError()

    def is_token_expired(self, token):
        raise NotImplementedError()

    def validate_request(self, headers, scope):
        auth = headers.get('Authorization')
        if not auth:
            raise ValueError()

        token_type, token_string = auth.split(None, 1)
        token = self.authenticate_token(token_string, token_type)
        if not token:
            raise ValueError()

        if self.is_token_expired(token):
            raise ValueError()

        token_scopes = set(scope_to_list(self.get_token_scope(token)))
        requested_scopes = set(scope_to_list(scope))
        if not token_scopes.issuperset(requested_scopes):
            raise ValueError()

        return token
