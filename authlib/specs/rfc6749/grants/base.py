from authlib.common.urls import extract_basic_authorization
from ..errors import (
    InvalidRequestError,
    InvalidScopeError,
    InvalidClientError,
)
from ..util import scope_to_list


class BaseGrant(object):
    AUTHORIZATION_ENDPOINT = False
    ACCESS_TOKEN_ENDPOINT = False
    ACCESS_TOKEN_METHODS = ['POST']
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

    def __init__(self, uri, params, headers, client_model, token_generator):
        self.headers = headers
        self.uri = uri
        self.params = params or {}
        self.client_model = client_model
        self.token_generator = token_generator
        self.state = params.get('state')
        self.redirect_uri = self.params.get('redirect_uri')
        self._clients = {}

    @property
    def client(self):
        return self.get_client_by_id(self.params['client_id'])

    @property
    def scopes(self):
        if 'scope' in self.params:
            return scope_to_list(self.params['scope'])

    def get_client_by_id(self, client_id):
        if client_id in self._clients:
            return self._clients[client_id]
        client = self.client_model.get_by_client_id(client_id)
        self._clients[client_id] = client
        return client

    def get_and_validate_client(self, client_id):
        if client_id is None:
            raise InvalidClientError(
                state=self.state,
                uri=self.uri,
            )

        client = self.get_client_by_id(client_id)
        if not client:
            raise InvalidClientError(
                state=self.state,
                uri=self.uri,
            )
        return client

    def parse_basic_auth_header(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header and ' ' in auth_header:
            auth_type, auth_token = auth_header.split(None, 1)
            if auth_type.lower() == 'basic':
                return extract_basic_authorization(auth_token)

    def validate_authorization_redirect_uri(self, client):
        if self.redirect_uri:
            if not client.check_redirect_uri(self.redirect_uri):
                raise InvalidRequestError(
                    'Invalid "redirect_uri" in request.',
                    state=self.state,
                    uri=self.uri,
                )
        else:
            redirect_uri = client.get_default_redirect_uri()
            if not redirect_uri:
                raise InvalidRequestError(
                    'Missing "redirect_uri" in request.'
                )
            self.redirect_uri = redirect_uri

    def validate_requested_scope(self, client):
        scopes = self.scopes
        if scopes and not client.check_requested_scopes(set(scopes)):
            raise InvalidScopeError(state=self.state, uri=self.uri)
