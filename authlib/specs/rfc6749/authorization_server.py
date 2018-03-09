from authlib.common.urls import add_params_to_uri
from authlib.deprecate import deprecate
from .errors import InvalidGrantError, OAuth2Error


class AuthorizationServer(object):
    """Authorization server that handles Authorization Endpoint and Token
    Endpoint.

    :param query_client: A function to get client by client_id. The client
        model class MUST implement the methods described by
        :class:`~authlib.specs.rfc6749.ClientMixin`.
    :param token_generator: A method to generate tokens.
    """
    def __init__(self, query_client, generate_token, save_token, **config):
        self.query_client = query_client
        self.generate_token = generate_token
        self.save_token = save_token
        self.config = config
        self._authorization_grants = []
        self._token_grants = []
        self._hooks = {}
        self._endpoints = {}

    def register_grant_endpoint(self, grant_cls):  # pragma: no cover
        deprecate('Use `register_grant` instead.', '0.8', 'vAAUK', 'rg')
        self.register_grant(grant_cls)

    def register_grant(self, grant_cls):
        """Register a grant class into the endpoint registry. Developers
        can implement the grants in ``authlib.specs.rfc6749.grants`` and
        register with this method::

            class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
                def authenticate_user(self, credential):
                    # ...

            authorization_server.register_grant(AuthorizationCodeGrant)

        :param grant_cls: a grant class.
        """
        if grant_cls.AUTHORIZATION_ENDPOINT:
            self._authorization_grants.append(grant_cls)
        if grant_cls.TOKEN_ENDPOINT:
            self._token_grants.append(grant_cls)

    def register_endpoint(self, endpoint_cls):
        self._endpoints[endpoint_cls.ENDPOINT_NAME] = endpoint_cls

    def register_hook(self, name, func):
        if name in self._hooks:
            raise ValueError('"{}" is already in hooks'.format(name))
        self._hooks[name] = func

    def execute_hook(self, name, *args, **kwargs):
        if name not in self._hooks:
            raise RuntimeError('"{}" hook is not registered.'.format(name))
        func = self._hooks[name]
        return func(*args, **kwargs)

    def get_authorization_grant(self, request):
        """Find the authorization grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for grant_cls in self._authorization_grants:
            if grant_cls.check_authorization_endpoint(request):
                return grant_cls(request, self)
        raise InvalidGrantError()

    def get_token_grant(self, request):
        """Find the token grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for grant_cls in self._token_grants:
            if grant_cls.check_token_endpoint(request):
                if request.method in grant_cls.TOKEN_ENDPOINT_HTTP_METHODS:
                    return grant_cls(request, self)
        raise InvalidGrantError()

    def create_endpoint_response(self, name, request):
        if name not in self._endpoints:
            raise RuntimeError('There is no "{}" endpoint.'.format(name))
        endpoint_cls = self._endpoints[name]
        endpoint = endpoint_cls(request, self)
        return endpoint()

    def create_valid_authorization_response(self, request, grant_user):
        """Validate authorization request and create authorization response.

        :param request: OAuth2Request instance.
        :param grant_user: if granted, it is resource owner. If denied,
            it is None.
        :returns: (status_code, body, headers)
        """
        # TODO: rename it to `create_authorization_response` in v0.8
        try:
            grant = self.get_authorization_grant(request)
        except InvalidGrantError as error:
            body = dict(error.get_body())
            return error.status_code, body, error.get_headers()
        try:
            grant.validate_authorization_request()
            return grant.create_authorization_response(grant_user)
        except OAuth2Error as error:
            if grant.redirect_uri:
                params = error.get_body()
                loc = add_params_to_uri(grant.redirect_uri, params)
                headers = [('Location', loc)]
                return 302, '', headers
            return 400, dict(error.get_body()), error.get_headers()

    def create_token_response(self, request):
        """Validate token request and create token response.

        :param request: OAuth2Request instance
        """
        try:
            grant = self.get_token_grant(request)
        except InvalidGrantError as error:
            payload = dict(error.get_body())
            return error.status_code, payload, error.get_headers()
        try:
            grant.validate_token_request()
            return grant.create_token_response()
        except OAuth2Error as error:
            status = error.status_code
            payload = dict(error.get_body())
            headers = error.get_headers()
            return status, payload, headers
