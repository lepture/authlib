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

    def __init__(self, request, query_client, token_generator):
        self.request = request
        self.redirect_uri = request.redirect_uri
        self.query_client = query_client
        self.token_generator = token_generator
        self._clients = {}

    @property
    def client(self):
        return self.get_client_by_id(self.request.client_id)

    @property
    def scopes(self):
        return scope_to_list(self.request.scope)

    def get_client_by_id(self, client_id):
        if client_id in self._clients:
            return self._clients[client_id]
        client = self.query_client(client_id)
        self._clients[client_id] = client
        return client

    def get_and_validate_client(self, client_id):
        if client_id is None:
            raise InvalidClientError(
                state=self.request.state,
            )

        client = self.get_client_by_id(client_id)
        if not client:
            raise InvalidClientError(
                state=self.request.state,
            )
        return client

    def validate_authorization_redirect_uri(self, client):
        if self.redirect_uri:
            if not client.check_redirect_uri(self.redirect_uri):
                raise InvalidRequestError(
                    'Invalid "redirect_uri" in request.',
                    state=self.request.state,
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
            raise InvalidScopeError(state=self.request.state)
