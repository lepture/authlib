from authlib.deprecate import deprecate
from .authenticate_client import ClientAuthentication
from .errors import InvalidGrantError, OAuth2Error


class AuthorizationServer(object):
    """Authorization server that handles Authorization Endpoint and Token
    Endpoint.

    :param query_client: A function to get client by client_id. The client
        model class MUST implement the methods described by
        :class:`~authlib.oauth2.rfc6749.ClientMixin`.
    :param token_generator: A method to generate tokens.
    """
    def __init__(self, query_client, generate_token, save_token, **config):
        self.query_client = query_client
        self.generate_token = generate_token
        self.save_token = save_token
        self.config = config
        if query_client:
            self.authenticate_client = ClientAuthentication(query_client)
        else:
            self.authenticate_client = None

        self._authorization_grants = []
        self._token_grants = []
        self._hooks = {}
        self._endpoints = {}

    def register_client_auth_method(self, method, func):
        """Add more client auth method. The default methods are:

        * none: The client is a public client and does not have a client secret
        * client_secret_post: The client uses the HTTP POST parameters
        * client_secret_basic: The client uses HTTP Basic

        :param method: Name of the Auth method
        :param func: Function to authenticate the client

        The auth method accept two parameters: ``query_client`` and ``request``,
        an example for this method::

            def authenticate_client_via_custom(query_client, request):
                client_id = request.headers['X-Client-Id']
                client = query_client(client_id)
                do_some_validation(client)
                return client

            authorization_server.register_client_auth_method(
                'custom', authenticate_client_via_custom)
        """
        self.authenticate_client.register(method, func)

    def get_translations(self, request):
        """Return a translations instance used for i18n error messages.
        Framework SHOULD implement this function.
        """
        return None

    def get_error_uris(self, request):
        error_uris = self.config.get('error_uris')
        if error_uris:
            return dict(error_uris)

    def send_signal(self, name, *args, **kwargs):
        raise NotImplementedError()

    def create_oauth2_request(self, request):
        """This method MUST be implemented in framework integrations. It is
        used to create an OAuth2Request instance.

        :param request: the "request" instance in framework
        :return: OAuth2Request instance
        """
        raise NotImplementedError()

    def handle_response(self, status, body, headers):
        """Return HTTP response. Framework MUST implement this function."""
        raise NotImplementedError()

    def register_grant(self, grant_cls, extensions=None):
        """Register a grant class into the endpoint registry. Developers
        can implement the grants in ``authlib.oauth2.rfc6749.grants`` and
        register with this method::

            class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
                def authenticate_user(self, credential):
                    # ...

            authorization_server.register_grant(AuthorizationCodeGrant)

        :param grant_cls: a grant class.
        :param extensions: extensions for the grant class.
        """
        if grant_cls.AUTHORIZATION_ENDPOINT:
            self._authorization_grants.append((grant_cls, extensions))
        if grant_cls.TOKEN_ENDPOINT:
            self._token_grants.append((grant_cls, extensions))

    def register_endpoint(self, endpoint_cls):
        """Add token endpoint to authorization server. e.g.
        RevocationEndpoint::

            authorization_server.register_endpoint(RevocationEndpoint)

        :param endpoint_cls: A token endpoint class
        """
        self._endpoints[endpoint_cls.ENDPOINT_NAME] = endpoint_cls

    def get_authorization_grant(self, request):
        """Find the authorization grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for (grant_cls, extensions) in self._authorization_grants:
            if grant_cls.check_authorization_endpoint(request):
                return _create_grant(grant_cls, extensions, request, self)
        raise InvalidGrantError()

    def get_token_grant(self, request):
        """Find the token grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for (grant_cls, extensions) in self._token_grants:
            if grant_cls.check_token_endpoint(request) and \
                    request.method in grant_cls.TOKEN_ENDPOINT_HTTP_METHODS:
                return _create_grant(grant_cls, extensions, request, self)
        raise InvalidGrantError()

    def create_endpoint_response(self, name, request=None):
        """Validate endpoint request and create endpoint response.

        :param name: Endpoint name
        :param request: OAuth2Request instance.
        :return: Response
        """
        if name not in self._endpoints:
            raise RuntimeError('There is no "{}" endpoint.'.format(name))

        request = self.create_oauth2_request(request)
        endpoint_cls = self._endpoints[name]
        endpoint = endpoint_cls(request, self)
        return self.handle_response(*endpoint())

    def create_authorization_response(self, request=None, grant_user=None):
        """Validate authorization request and create authorization response.

        :param request: OAuth2Request instance.
        :param grant_user: if granted, it is resource owner. If denied,
            it is None.
        :returns: Response
        """
        request = self.create_oauth2_request(request)
        try:
            grant = self.get_authorization_grant(request)
        except InvalidGrantError as error:
            return self.handle_error_response(request, error)

        try:
            grant.validate_authorization_request()
            args = grant.create_authorization_response(grant_user)
            return self.handle_response(*args)

        except OAuth2Error as error:
            if grant.redirect_uri:
                data = grant.create_authorization_error_response(error)
                return self.handle_response(*data)
            return self.handle_error_response(request, error)

    def create_token_response(self, request=None):
        """Validate token request and create token response.

        :param request: OAuth2Request instance
        """
        request = self.create_oauth2_request(request)
        try:
            grant = self.get_token_grant(request)
        except InvalidGrantError as error:
            return self.handle_error_response(request, error)

        try:
            grant.validate_token_request()
            args = grant.create_token_response()
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    def handle_error_response(self, request, error):
        return self.handle_response(*error(
            translations=self.get_translations(request),
            error_uris=self.get_error_uris(request)
        ))

    def register_hook(self, name, func):  # pragma: no cover
        deprecate('.register_hook is deprecated', '0.12', 'fAmW1', 'OC')
        if name in self._hooks:
            raise ValueError('"{}" is already in hooks'.format(name))
        self._hooks[name] = func

    def execute_hook(self, name, *args, **kwargs):  # pragma: no cover
        deprecate('.execute_hook is deprecated', '0.12', 'fAmW1', 'OC')
        if name not in self._hooks:
            raise RuntimeError('"{}" hook is not registered.'.format(name))
        func = self._hooks[name]
        return func(*args, **kwargs)


def _create_grant(grant_cls, extensions, request, server):
    grant = grant_cls(request, server)
    if extensions:
        for ext in extensions:
            ext(grant)
    return grant
