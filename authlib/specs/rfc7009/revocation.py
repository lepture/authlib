from authlib.common.urls import extract_basic_authorization
from .errors import (
    OAuth2Error,
    InvalidRequestError,
    UnsupportedTokenTypeError,
    InvalidClientError,
)


class RevocationEndpoint(object):
    supported_token_types = ('access_token', 'refresh_token')

    def __init__(self, uri, params, headers, client_model):
        self.uri = uri
        self.params = params
        self.headers = headers
        self.client_model = client_model
        self._token = None
        self._client = None

    def parse_basic_auth_header(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header and ' ' in auth_header:
            auth_type, auth_token = auth_header.split(None, 1)
            if auth_type.lower() == 'basic':
                return extract_basic_authorization(auth_token)

    def validate_authenticate_client(self):
        client_params = self.parse_basic_auth_header()
        if not client_params:
            raise InvalidClientError(uri=self.uri)

        client_id, client_secret = client_params
        client = self.client_model.get_by_client_id(client_id)
        if not client:
            raise InvalidClientError(uri=self.uri)

        if client.client_secret != client_secret:
            raise InvalidClientError(uri=self.uri)

        self._client = client

    def validate_revocation_request(self):
        """The client constructs the request by including the following
        parameters using the "application/x-www-form-urlencoded" format in
        the HTTP request entity-body:

        token
            REQUIRED.  The token that the client wants to get revoked.

        token_type_hint
            OPTIONAL.  A hint about the type of the token submitted for
            revocation.
        """
        if 'token' not in self.params:
            raise InvalidRequestError(uri=self.uri)

        token_type = self.params.get('token_type_hint')
        if token_type and token_type not in self.supported_token_types:
            raise UnsupportedTokenTypeError(uri=self.uri)
        token = self.query_token(
            self.params['token'], token_type, self._client
        )
        if not token:
            raise InvalidRequestError(uri=self.uri)
        self._token = token

    def create_revocation_response(self):
        try:
            # The authorization server first validates the client credentials
            self.validate_authenticate_client()
            # then verifies whether the token was issued to the client making
            # the revocation request
            self.validate_revocation_request()
            # the authorization server invalidates the token
            self.invalidate_token(self._token)
            status = 200
            body = {}
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
        raise NotImplementedError()

    def invalidate_token(self, token):
        raise NotImplementedError()
