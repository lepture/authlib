from .base import BaseGrant
from ..errors import (
    UnauthorizedClientError,
    InvalidClientError,
)


class ClientCredentialsGrant(BaseGrant):
    """The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner that have been previously
    arranged with the authorization server.

    The client credentials grant type MUST only be used by confidential
    clients::

        +---------+                                  +---------------+
        |         |                                  |               |
        |         |>--(A)- Client Authentication --->| Authorization |
        | Client  |                                  |     Server    |
        |         |<--(B)---- Access Token ---------<|               |
        |         |                                  |               |
        +---------+                                  +---------------+

    https://tools.ietf.org/html/rfc6749#section-4.4
    """
    ACCESS_TOKEN_ENDPOINT = True
    GRANT_TYPE = 'client_credentials'

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(ClientCredentialsGrant, self).__init__(
            uri, params, headers, client_model, token_generator)
        self._authenticated_client = None

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == ClientCredentialsGrant.GRANT_TYPE

    def validate_access_token_request(self):
        """The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body:

        grant_type
             REQUIRED.  Value MUST be set to "client_credentials".

        scope
             OPTIONAL.  The scope of the access request as described by
             Section 3.3.

        The client MUST authenticate with the authorization server as
        described in Section 3.2.1.

        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display purposes
        only):

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=client_credentials

        The authorization server MUST authenticate the client.
        """

        # ignore validate for grant_type, since it is validated by
        # check_token_endpoint
        client = self.authenticate_client()

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)

        self.validate_requested_scope(client)
        self._authenticated_client = client

    def create_access_token_response(self):
        """If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        Section 5.1.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in Section 5.2.

        An example successful response:

        .. code-block:: http

            HTTP/1.1 200 OK
            Content-Type: application/json
            Cache-Control: no-store
            Pragma: no-cache

            {
                "access_token":"2YotnFZFEjr1zCsicMWpAA",
                "token_type":"example",
                "expires_in":3600,
                "example_parameter":"example_value"
            }

        :returns: (status_code, body, headers)
        """
        token = self.token_generator(
            self._authenticated_client, self.GRANT_TYPE,
            scope=self.params.get('scope'),
            include_refresh_token=False,
        )
        self.create_access_token(token, self._authenticated_client)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def authenticate_client(self):
        """Authenticate client with Basic Authorization. Developers who want
        to use other means for authentication can re-implement it in subclass.

        :return: client
        """
        client_params = self.parse_basic_auth_header()
        if not client_params:
            raise InvalidClientError(uri=self.uri)

        client_id, client_secret = client_params
        client = self.get_and_validate_client(client_id)

        # authenticate the client if client authentication is included
        if client_secret != client.client_secret:
            raise InvalidClientError(uri=self.uri)

        return client

    def create_access_token(self, token, client):
        """Save access_token into database. Developers should implement it in
        subclass::

            def create_access_token(self, token, client):
                item = Token(
                    client_id=client.client_id,
                    user_id=client.user_id,
                    **token
                )
                item.save()

        :param token: A dict contains the token information.
        :param client: Current client related to the token.
        """
        raise NotImplementedError()
