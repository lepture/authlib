from authlib.common.urls import add_params_to_uri
from ..errors import (
    InvalidRequestError,
    InvalidScopeError,
)
from ..util import scope_to_list


class BaseGrant(object):
    SPECIFICATION = 'rfc6749'
    #: If this grant type has authorization endpoint
    AUTHORIZATION_ENDPOINT = False
    #: If this grant type has token endpoint
    TOKEN_ENDPOINT = False
    #: Allowed HTTP methods of this token endpoint
    TOKEN_ENDPOINT_HTTP_METHODS = ['POST']
    #: Allowed client auth methods for token endpoint
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']
    RESPONSE_TYPE = None
    GRANT_TYPE = None

    # NOTE: there is no charset for application/json, since
    # application/json should always in UTF-8.
    # The example on RFC is incorrect.
    # https://tools.ietf.org/html/rfc4627
    TOKEN_RESPONSE_HEADER = [
        ('Content-Type', 'application/json'),
        ('Cache-Control', 'no-store'),
        ('Pragma', 'no-cache'),
    ]

    def __init__(self, request, server):
        self.request = request
        self.redirect_uri = request.redirect_uri
        self.server = server
        self._hooks = {
            'after_validate_authorization_request': set(),
            'after_validate_consent_request': set(),
            'after_validate_token_request': set(),
            'process_token': set(),
        }

    @classmethod
    def check_token_endpoint(cls, request):
        return request.grant_type == cls.GRANT_TYPE

    @property
    def client(self):
        return self.request.client

    def generate_token(self, client, grant_type, user=None, scope=None,
                       expires_in=None, include_refresh_token=True):
        return self.server.generate_token(
            client, grant_type,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )

    def authenticate_token_endpoint_client(self):
        """Authenticate client with the given methods for token endpoint.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        Default available methods are: "none", "client_secret_basic" and
        "client_secret_post".

        :return: client
        """
        client = self.server.authenticate_client(
            self.request,
            self.TOKEN_ENDPOINT_AUTH_METHODS)
        self.server.send_signal(
            'after_authenticate_client',
            client=client, grant=self)
        return client

    def validate_requested_scope(self, client):
        scopes = scope_to_list(self.request.scope)
        if scopes and not client.check_requested_scopes(set(scopes)):
            raise InvalidScopeError(state=self.request.state)

    def register_hook(self, hook_type, hook):
        if hook_type not in self._hooks:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self._hooks)
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in self._hooks[hook_type]:
            hook(self, *args, **kwargs)


class RedirectAuthGrant(BaseGrant):
    ERROR_RESPONSE_FRAGMENT = False

    @classmethod
    def check_authorization_endpoint(cls, request):
        return request.response_type == cls.RESPONSE_TYPE

    def validate_authorization_request(self):
        raise NotImplementedError()

    def validate_consent_request(self):
        self.validate_authorization_request()
        self.execute_hook('after_validate_consent_request')

    def validate_authorization_redirect_uri(self, client):
        if self.redirect_uri:
            if not client.check_redirect_uri(self.redirect_uri):
                self.redirect_uri = None
                raise InvalidRequestError(
                    'Invalid "redirect_uri" in request.',
                    state=self.request.state,
                )
        else:
            redirect_uri = client.get_default_redirect_uri()
            if not redirect_uri:
                raise InvalidRequestError(
                    'Missing "redirect_uri" in request.'
                )
            self.redirect_uri = redirect_uri

    def create_authorization_error_response(self, error):
        params = error.get_body()
        loc = add_params_to_uri(self.redirect_uri, params, self.ERROR_RESPONSE_FRAGMENT)
        return 302, '', [('Location', loc)]
