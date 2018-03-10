from ..rfc7009.errors import (
    OAuth2Error,
    InvalidRequestError,
    UnsupportedTokenTypeError,
)
from ..rfc6749 import authenticate_client


__all__ = [
    'IntrospectionEndpoint',
]


class IntrospectionEndpoint(object):
    """Implementation of introspection endpoint which is described in
    `RFC7662`_.

    :param request: OAuth2Request instance
    :param query_client: A function to get client by client_id. The client
        model class MUST implement the methods described by
        :class:`~authlib.specs.rfc6749.ClientMixin`.

    .. _RFC7662: https://tools.ietf.org/html/rfc7662
    """
    SUPPORTED_TOKEN_TYPES = ('access_token', 'refresh_token')
    INTROSPECTION_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, request, query_client):
        self.request = request
        self.query_client = query_client

        self._client = None
        self._token = None

    def authenticate_introspection_endpoint_client(self):
        """Authentication client for introspection endpoint with
        ``INTROSPECTION_ENDPOINT_AUTH_METHODS``.
        """
        self._client = authenticate_client(
            self.query_client,
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

        self._token = self.query_token(
            params['token'],
            self._client,
            optional={k: v for k, v in params.items() if k != 'token'}
        )
        if not self._token:
            raise InvalidRequestError()

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

    def query_token(self, token, client, optional=None):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token, client, optional=None):
                if optional is None:
                    optional = {}

                token_type_hint = optional.get('token_type_hint')
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
        dictionary following RFC7662 keys.
        """
        raise NotImplementedError()
