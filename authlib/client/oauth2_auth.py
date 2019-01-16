from requests.auth import AuthBase
from authlib.oauth2.rfc6749 import AuthClient
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc6750 import add_bearer_token
from .errors import (
    MissingTokenError,
    UnsupportedTokenTypeError,
)


class OAuth2Auth(AuthBase):
    """Sign requests for OAuth 2.0, currently only bearer token is supported.

    :param token: A dict or OAuth2Token instance of an OAuth 2.0 token
    :param token_placement: The placement of the token, default is ``header``,
        available choices:

        * header (default)
        * body
        * uri
    """
    SIGN_METHODS = {
        'bearer': add_bearer_token
    }

    @classmethod
    def register_sign_method(cls, sign_type, func):
        cls.SIGN_METHODS[sign_type] = func

    def __init__(self, token, token_placement='header'):
        self.token = OAuth2Token.from_dict(token)
        self.token_placement = token_placement
        self.hooks = set()

    def __call__(self, req):
        if not self.token:
            raise MissingTokenError()

        token_type = self.token['token_type']
        sign = self.SIGN_METHODS.get(token_type.lower())
        if not sign:
            description = 'Unsupported token_type "{}"'.format(token_type)
            raise UnsupportedTokenTypeError(description=description)

        url, headers, body = sign(
            self.token['access_token'],
            req.url, req.headers, req.body,
            self.token_placement)

        for hook in self.hooks:
            url, headers, body = hook(url, headers, body)

        req.url = url
        req.headers = headers
        req.body = body
        return req


class OAuth2ClientAuth(AuthBase, AuthClient):
    """Attaches OAuth Client Authentication to the given Request object.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param auth_method: Client auth method for token endpoint. The supported
        methods for now:

        * client_secret_basic
        * client_secret_post
        * none
    """
    def __call__(self, req):
        req.url, req.headers, req.body = self.prepare(
            req.method, req.url, req.headers, req.body
        )
        return req
