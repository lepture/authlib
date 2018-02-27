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
    RESPONSE_TYPE = None
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
        self.scopes = scope_to_list(request.scope)
        self.query_client = query_client
        self.token_generator = token_generator
        self._clients = {}

    @property
    def client(self):
        return self.get_client_by_id(self.request.client_id)

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

    def authenticate_via_client_secret_basic(self):
        """Authenticate client by ``client_secret_basic`` method. The client
        uses HTTP Basic for authentication.
        """
        client_id, client_secret = self.request.extract_authorization_header()
        if client_id and client_secret:
            client = self.get_and_validate_client(client_id)
            if client.check_token_endpoint_auth_method('client_secret_basic') \
                    and client.check_client_secret(client_secret):
                return client

    def authenticate_via_client_secret_post(self):
        """Authenticate client by ``client_secret_post`` method. The client
        uses POST parameters for authentication.
        """
        data = dict(self.request.body_params)
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        if client_id and client_secret:
            client = self.get_and_validate_client(client_id)
            if client.check_token_endpoint_auth_method('client_secret_post') \
                    and client.check_client_secret(client_secret):
                return client

    def authenticate_via_none(self):
        """Authenticate public client by ``none`` method. The client
        does not have a client secret.
        """
        client_id = self.request.client_id
        if client_id and 'client_secret' not in self.request.data:
            client = self.get_and_validate_client(client_id)
            if client.check_token_endpoint_auth_method('none') \
                    and not client.has_client_secret():
                return client

    def validate_requested_scope(self, client):
        scopes = self.scopes
        if scopes and not client.check_requested_scopes(set(scopes)):
            raise InvalidScopeError(state=self.request.state)


class RedirectAuthGrant(BaseGrant):
    @classmethod
    def check_authorization_endpoint(cls, request):
        return request.response_type == cls.RESPONSE_TYPE

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


class ClientAuthGrant(BaseGrant):
    @classmethod
    def check_token_endpoint(cls, request):
        return request.grant_type == cls.GRANT_TYPE

    def authenticate_client(self):
        """Authenticate client with ``client_secret_basic`` or
        ``client_secret_post``. Developers who want to use other means for
        authentication can re-implement it in subclass.

        :return: client
        """
        client = self.authenticate_via_client_secret_basic()
        if client:
            return client
        client = self.authenticate_via_client_secret_post()
        if client:
            return client
        raise InvalidClientError()
