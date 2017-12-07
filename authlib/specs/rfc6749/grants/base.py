from authlib.common.urls import url_decode, urlparse
from ..errors import (
    InvalidRequestError,
    UnauthorizedClientError,
)
from ..util import extract_basic_authorization


class BaseGrant(object):
    AUTHORIZATION_ENDPOINT = False
    ACCESS_TOKEN_ENDPOINT = False

    def __init__(self, method, uri, body, headers, client_model, params=None):
        self.method = method
        self.body = body
        self.headers = headers
        self.uri = uri

        if params is None:
            if method == 'GET':
                params = dict(url_decode(urlparse.urlparse(uri).query))
            elif method == 'POST':
                params = url_decode(body)

        self.params = params or {}
        self.client_model = client_model
        self._clients = {}

    def get_client_by_id(self, client_id):
        if client_id in self._clients:
            return self._clients[client_id]
        client = self.client_model.get_by_id(client_id)
        self._clients[client_id] = client
        return client

    def get_and_validate_client(self, client_id, state=None):
        if client_id is None:
            raise InvalidRequestError(
                'Missing "client_id" in request.',
                state=state,
                uri=self.uri,
            )

        client = self.get_client_by_id(client_id)
        if not client:
            raise InvalidRequestError(
                'Invalid "client_id" value in request.',
                state=state,
                uri=self.uri,
            )
        return client

    def parse_client_id_and_secret(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header and ' ' in auth_header:
            auth_type, auth_token = auth_header.split(maxsplit=1)
            if auth_token.lower() == 'basic':
                return extract_basic_authorization(auth_token)

        return self.params.get('client_id'), self.params.get('client_secret')

    def authenticate_client(self, client_id, client_secret=None):
        """Authenticate client with client_id and client_secret.

        require client authentication for confidential clients or for any
        client that was issued client credentials

        :param client_id:
        :param client_secret:
        :return: client
        """
        client = self.get_and_validate_client(client_id)
        if client.check_client_type('confidential'):
            if client_secret is None:
                raise InvalidRequestError(
                    'Missing "client_secret" in request.',
                    uri=self.uri,
                )
            if client_secret != client.client_secret:
                raise UnauthorizedClientError(uri=self.uri)
            return client

        if client_secret is not None:
            if client_secret != client.client_secret:
                raise UnauthorizedClientError(uri=self.uri)

        return client
