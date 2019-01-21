from authlib.common.errors import AuthlibBaseError, AuthlibHTTPError


class OAuth2Error(AuthlibHTTPError):
    def __init__(self, description=None, uri=None,
                 status_code=None, state=None):
        super(OAuth2Error, self).__init__(None, description, uri, status_code)
        self.state = state

    def get_body(self):
        """Get a list of body."""
        error = super(OAuth2Error, self).get_body()
        if self.state:
            error.append(('state', self.state))
        return error
