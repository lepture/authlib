"""
    authlib.specs.rfc6749.resource_protector
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Accessing Protected Resources per `Section 7`_.

    .. _`Section 7`: https://tools.ietf.org/html/rfc6749#section-7
"""


class ResourceProtector(object):
    def __init__(self, token_validator):
        self.token_validator = token_validator

    def authenticate_token(self, token_string, token_type):
        """
        :param token_string: A string to represent the access_token.
        :param token_type: The token_type of the access_token.
        :return: token
        """
        raise NotImplementedError()

    def validate_request(self, scope, method, uri, body, headers):
        auth = headers.get('Authorization')
        if not auth:
            token = None
        else:
            # https://tools.ietf.org/html/rfc6749#section-7.1
            token_type, token_string = auth.split(None, 1)
            token = self.authenticate_token(token_string, token_type)

        self.token_validator(token, scope, method, uri, body, headers)
        return token
