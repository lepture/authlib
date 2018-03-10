from authlib.specs.rfc6749 import (
    OAuth2Error,
    InvalidRequestError,
    UnsupportedTokenTypeError,
)
from authlib.specs.rfc6749 import authenticate_client


class IntrospectionEndpoint(object):
    """Implementation of introspection endpoint which is described in
    `RFC7662`_.

    :param request: OAuth2Request instance
    :param server: Authorization Server instance

    .. _RFC7662: https://tools.ietf.org/html/rfc7662
    """
    ENDPOINT_NAME = 'introspection'
    SUPPORTED_TOKEN_TYPES = ('access_token', 'refresh_token')
    INTROSPECTION_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, request, server):
        self.request = request
        self.server = server

        self._client = None
        self._token = None

    def __call__(self):
        return self.create_introspection_response()

    def authenticate_introspection_endpoint_client(self):
        """Authentication client for introspection endpoint with
        ``INTROSPECTION_ENDPOINT_AUTH_METHODS``.
        """
        self._client = authenticate_client(
            self.server.query_client,
            request=self.request,
            methods=self.INTROSPECTION_ENDPOINT_AUTH_METHODS,
        )

    def validate_introspection_request(self):
        """The protected resource calls the introspection endpoint using an HTTP
        ``POST`` request with parameters sent as
        "application/x-www-form-urlencoded" data. The protected resource sends a
        parameter representing the token along with optional parameters
        representing additional context that is known by the protected resource
        to aid the authorization server in its response.

        token
            **REQUIRED**  The string value of the token. For access tokens, this
            is the ``access_token`` value returned from the token endpoint
            defined in OAuth 2.0. For refresh tokens, this is the
            ``refresh_token`` value returned from the token endpoint as defined
            in OAuth 2.0.

        token_type_hint
            **OPTIONAL**  A hint about the type of the token submitted for
            introspection.
        """
        if self.request.body_params:
            params = dict(self.request.body_params)
        else:
            raise InvalidRequestError()

        if 'token' not in params:
            raise InvalidRequestError()

        token_type = params.get('token_type_hint')
        if token_type and token_type not in self.SUPPORTED_TOKEN_TYPES:
            raise UnsupportedTokenTypeError()

        token = self.query_token(
            params['token'], token_type, self._client)
        if not token:
            raise InvalidRequestError()
        self._token = token

    def create_introspection_response(self):
        """Validate introspection request and create the response.

        :returns: (status_code, body, headers)
        """
        try:
            # The authorization server first validates the client credentials
            self.authenticate_introspection_endpoint_client()
            # then verifies whether the token was issued to the client making
            # the revocation request
            self.validate_introspection_request()
            # the authorization server invalidates the token
            body = self.introspect_token(self._token)
            status = 200
            headers = [
                ('Content-Type', 'application/json'),
                ('Cache-Control', 'no-store'),
                ('Pragma', 'no-cache'),
            ]
        except OAuth2Error as error:
            status = error.status_code
            body = dict(error.get_body())
            headers = error.get_headers()

        return status, body, headers

    def query_token(self, token, token_type_hint, client):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token, token_type_hint, client):
                if token_type_hint == 'access_token':
                    return Token.query_by_access_token(token, client.client_id)
                if token_type_hint == 'refresh_token':
                    return Token.query_by_refresh_token(token, client.client_id)
                return Token.query_by_access_token(token, client.client_id) or \
                    Token.query_by_refresh_token(token, client.client_id)
        """
        raise NotImplementedError()

    def introspect_token(self, token):
        """Read given token and return its introspection metadata as a
        dictionary following `Section 2.2`_::

            def introspect_token(self, token):
                user = User.query.get(token.user_id)
                return {
                    "active": not token.revoked,
                    "client_id": token.client_id,
                    "username": user.username,
                    "scope": token.scope,
                    "sub": user.sub,
                    "aud": token.client_id,
                    "iss": "https://server.example.com/",
                    "exp": token.expires_at,
                    "iat": token.issued_at,
                }

        .. _`Section 2.2`: https://tools.ietf.org/html/rfc7662#section-2.2
        """
        raise NotImplementedError()
