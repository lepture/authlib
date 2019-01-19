from requests.auth import AuthBase
from authlib.oauth2.client import ClientAuth, TokenAuth
from .errors import (
    MissingTokenError,
    UnsupportedTokenTypeError,
)


class OAuth2Auth(AuthBase, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""

    def __call__(self, req):
        if not self.token:
            raise MissingTokenError()
        try:
            req.url, req.headers, req.body = self.prepare(
                req.url, req.headers, req.body)

        except KeyError as error:
            description = 'Unsupported token_type: {}'.format(str(error))
            raise UnsupportedTokenTypeError(description=description)
        return req


class OAuth2ClientAuth(AuthBase, ClientAuth):
    """Attaches OAuth Client Authentication to the given Request object.
    """
    def __call__(self, req):
        req.url, req.headers, req.body = self.prepare(
            req.method, req.url, req.headers, req.body
        )
        return req
