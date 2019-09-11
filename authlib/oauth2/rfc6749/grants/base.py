from authlib.consts import default_json_headers
from ..errors import InvalidRequestError


class BaseGrant(object):
    #: Allowed client auth methods for token endpoint
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    # NOTE: there is no charset for application/json, since
    # application/json should always in UTF-8.
    # The example on RFC is incorrect.
    # https://tools.ietf.org/html/rfc4627
    TOKEN_RESPONSE_HEADER = default_json_headers

    def __init__(self, request, server):
        self.request = request
        self.server = server
        self._hooks = {
            'after_validate_authorization_request': set(),
            'after_validate_consent_request': set(),
            'after_validate_token_request': set(),
            'process_token': set(),
        }

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

    def save_token(self, token):
        """A method to save token into database."""
        return self.server.save_token(token, self.request)

    def validate_requested_scope(self):
        """Validate if requested scope is supported by Authorization Server."""
        scope = self.request.scope
        state = self.request.state
        return self.server.validate_requested_scope(scope, state)

    def register_hook(self, hook_type, hook):
        if hook_type not in self._hooks:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self._hooks)
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        for hook in self._hooks[hook_type]:
            hook(self, *args, **kwargs)


class TokenEndpointMixin(object):
    #: Allowed HTTP methods of this token endpoint
    TOKEN_ENDPOINT_HTTP_METHODS = ['POST']

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    @classmethod
    def check_token_endpoint(cls, request):
        return request.grant_type == cls.GRANT_TYPE

    def validate_token_request(self):
        raise NotImplementedError()

    def create_token_response(self):
        raise NotImplementedError()


class AuthorizationEndpointMixin(object):
    RESPONSE_TYPES = set()
    ERROR_RESPONSE_FRAGMENT = False

    @classmethod
    def check_authorization_endpoint(cls, request):
        return request.response_type in cls.RESPONSE_TYPES

    @staticmethod
    def validate_authorization_redirect_uri(request, client):
        if request.redirect_uri:
            if not client.check_redirect_uri(request.redirect_uri):
                raise InvalidRequestError(
                    'Invalid "redirect_uri" in request.',
                    state=request.state,
                )
            return request.redirect_uri
        else:
            redirect_uri = client.get_default_redirect_uri()
            if not redirect_uri:
                raise InvalidRequestError(
                    'Missing "redirect_uri" in request.'
                )
            return redirect_uri

    def validate_consent_request(self):
        redirect_uri = self.validate_authorization_request()
        self.execute_hook('after_validate_consent_request', redirect_uri)

    def validate_authorization_request(self):
        raise NotImplementedError()

    def create_authorization_response(self, redirect_uri, grant_user):
        raise NotImplementedError()
