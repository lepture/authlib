from .authenticate_client import authenticate_client


class TokenEndpoint(object):
    #: Endpoint name to be registered
    ENDPOINT_NAME = None
    #: Supported token types
    SUPPORTED_TOKEN_TYPES = ('access_token', 'refresh_token')
    #: Allowed client authenticate methods
    CLIENT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, request, server):
        self.request = request
        self.server = server
        self._token = None
        self._client = None

    def __call__(self):
        # make it callable for authorization server
        # ``create_endpoint_response``
        return self.create_endpoint_response()

    def authenticate_endpoint_client(self):
        """Authentication client for endpoint with ``CLIENT_AUTH_METHODS``.
        """
        self._client = authenticate_client(
            self.server.query_client,
            request=self.request,
            methods=self.CLIENT_AUTH_METHODS,
        )

    def validate_endpoint_request(self):
        raise NotImplementedError()

    def create_endpoint_response(self):
        raise NotImplementedError()
