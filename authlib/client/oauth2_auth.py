from requests.auth import AuthBase, HTTPBasicAuth
from ..common.urls import add_params_to_qs
from ..specs.rfc6749 import OAuth2Token
from ..specs.rfc6750 import add_bearer_token
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


class OAuth2ClientAuth(HTTPBasicAuth):
    """Attaches OAuth Client Authentication to the given Request object.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param auth_method: Client auth method for token endpoint. The supported
        methods for now:

        * client_secret_basic
        * client_secret_post
        * none
    """
    def __init__(self, client_id, client_secret,
                 auth_method='client_secret_basic'):
        super(OAuth2ClientAuth, self).__init__(client_id, client_secret)

        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_method = auth_method
        self._methods = {
            'none': _auth_none,
            'client_secret_post': _auth_client_secret_post,
        }

    def register(self, method, func):
        assert method not in self._methods
        self._methods[method] = func

    def __call__(self, req):
        if self.auth_method == 'client_secret_basic':
            return super(OAuth2ClientAuth, self).__call__(req)

        func = self._methods.get(self.auth_method)
        if func:
            req = func(self, req)
        return req


def _auth_none(auth, req):
    if req.method == 'GET':
        req.url = add_params_to_qs(req.url, [
            ('client_id', auth.client_id)
        ])
    elif req.method == 'POST':
        req.body = add_params_to_qs(req.body or '', [
            ('client_id', auth.client_id)
        ])
    return req


def _auth_client_secret_post(auth, req):
    req.body = add_params_to_qs(req.body or '', [
        ('client_id', auth.client_id),
        ('client_secret', auth.client_secret or '')
    ])
    return req
