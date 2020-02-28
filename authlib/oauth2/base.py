from authlib.common.errors import AuthlibHTTPError
from authlib.common.urls import add_params_to_uri


class OAuth2Error(AuthlibHTTPError):
    def __init__(self, description=None, uri=None,
                 status_code=None, state=None,
                 redirect_uri=None, redirect_fragment=False, error=None):
        super(OAuth2Error, self).__init__(error, description, uri, status_code)
        self.state = state
        self.redirect_uri = redirect_uri
        self.redirect_fragment = redirect_fragment

    def get_body(self):
        """Get a list of body."""
        error = super(OAuth2Error, self).get_body()
        if self.state:
            error.append(('state', self.state))
        return error

    def __call__(self, translations=None, error_uris=None):
        if self.redirect_uri:
            params = self.get_body()
            loc = add_params_to_uri(
                self.redirect_uri, params, self.redirect_fragment)
            return 302, '', [('Location', loc)]
        return super(OAuth2Error, self).__call__(translations, error_uris)
