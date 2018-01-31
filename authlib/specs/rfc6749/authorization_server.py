from authlib.common.urls import urlparse, url_decode
from authlib.common.urls import add_params_to_uri
from .errors import InvalidGrantError, InsecureTransportError, OAuth2Error


class AuthorizationServer(object):
    """Authorization server that handles Authorization Endpoint and Token
    Endpoint.

    :param client_model: A model class that implemented the methods described
        by :class:`~authlib.specs.rfc6749.ClientMixin`.
    :param token_generator: A method to generate tokens.
    """
    def __init__(self, client_model, token_generator):
        self.client_model = client_model
        self.token_generator = token_generator
        self._authorization_endpoints = set()
        self._token_endpoints = set()

    def register_grant_endpoint(self, grant_cls):
        """Register a grant class into the endpoint registry. Developers
        can implement the grants in ``authlib.specs.rfc6749.grants`` and
        register with this method::

            class MyImplicitGrant(ImplicitGrant):
                def create_access_token(self, token, client, grant_user):
                    # ...

            authorization_server.register_grant_endpoint(MyImplicitGrant)

        :param grant_cls: a grant class.
        """
        if grant_cls.AUTHORIZATION_ENDPOINT:
            self._authorization_endpoints.add(grant_cls)
        if grant_cls.ACCESS_TOKEN_ENDPOINT:
            self._token_endpoints.add(grant_cls)

    def get_authorization_grant(self, method, uri, body):
        """Find the authorization grant for current request.

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :return: grant instance
        """
        InsecureTransportError.check(uri)
        params = dict(url_decode(urlparse.urlparse(uri).query))

        if method == 'POST' and body:
            if isinstance(body, dict):
                params.update(body)
            else:
                params.update(dict(url_decode(body)))

        for grant_cls in self._authorization_endpoints:
            if grant_cls.check_authorization_endpoint(params):
                return grant_cls(
                    uri, params, {},
                    self.client_model,
                    self.token_generator
                )
        raise InvalidGrantError()

    def get_token_grant(self, method, uri, body, headers):
        """Find the token grant for current request.

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param headers: HTTP request headers.
        :return: grant instance
        """
        InsecureTransportError.check(uri)
        if method == 'GET':
            params = dict(url_decode(urlparse.urlparse(uri).query))
        else:
            if isinstance(body, dict):
                params = body
            else:
                params = dict(url_decode(body))

        for grant_cls in self._token_endpoints:
            if grant_cls.check_token_endpoint(params):
                if method in grant_cls.ACCESS_TOKEN_METHODS:
                    return grant_cls(
                        uri, params, headers,
                        self.client_model,
                        self.token_generator
                    )
        raise InvalidGrantError()

    def create_valid_authorization_response(self, method, uri, body, grant_user):
        """Validate authorization request and create authorization response.

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param grant_user: if granted, it is resource owner's ID. If denied,
            it is None.
        :returns: (status_code, body, headers)
        """
        try:
            grant = self.get_authorization_grant(method, uri, body)
        except InvalidGrantError as error:
            body = dict(error.get_body())
            return error.status_code, body, error.get_headers()
        try:
            grant.validate_authorization_request()
            return grant.create_authorization_response(grant_user)
        except OAuth2Error as error:
            params = error.get_body()
            loc = add_params_to_uri(grant.redirect_uri, params)
            headers = [('Location', loc)]
            return 302, '', headers

    def create_valid_token_response(self, method, uri, body, headers):
        """Validate token request and create token response.

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param headers: HTTP request headers.
        :returns: (status_code, body, headers)
        """
        try:
            grant = self.get_token_grant(method, uri, body, headers)
        except InvalidGrantError as error:
            payload = dict(error.get_body())
            return error.status_code, payload, error.get_headers()
        try:
            grant.validate_access_token_request()
            return grant.create_access_token_response()
        except OAuth2Error as error:
            status = error.status_code
            payload = dict(error.get_body())
            headers = error.get_headers()
            return status, payload, headers
