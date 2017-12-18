from .base import BaseGrant
from ..errors import (
    UnauthorizedClientError,
    InvalidClientError,
    InvalidRequestError,
    InvalidGrantError,
)


class ResourceOwnerPasswordCredentialsGrant(BaseGrant):
    """The resource owner password credentials grant type is suitable in
    cases where the resource owner has a trust relationship with the
    client, such as the device operating system or a highly privileged

    application.  The authorization server should take special care when
    enabling this grant type and only allow it when other flows are not
    viable.

    This grant type is suitable for clients capable of obtaining the
    resource owner's credentials (username and password, typically using
    an interactive form).  It is also used to migrate existing clients
    using direct authentication schemes such as HTTP Basic or Digest
    authentication to OAuth by converting the stored credentials to an
    access token::

        +----------+
        | Resource |
        |  Owner   |
        |          |
        +----------+
            v
            |    Resource Owner
           (A) Password Credentials
            |
            v
        +---------+                                  +---------------+
        |         |>--(B)---- Resource Owner ------->|               |
        |         |         Password Credentials     | Authorization |
        | Client  |                                  |     Server    |
        |         |<--(C)---- Access Token ---------<|               |
        |         |    (w/ Optional Refresh Token)   |               |
        +---------+                                  +---------------+
    """
    ACCESS_TOKEN_ENDPOINT = True
    GRANT_TYPE = 'password'

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(ResourceOwnerPasswordCredentialsGrant, self).__init__(
            uri, params, headers, client_model, token_generator)
        self._authenticated_client = None
        self._authenticated_user = None

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == 'password'

    def validate_access_token_request(self):
        """The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body:

        grant_type
             REQUIRED.  Value MUST be set to "password".

        username
             REQUIRED.  The resource owner username.

        password
             REQUIRED.  The resource owner password.

        scope
             OPTIONAL.  The scope of the access request as described by
             Section 3.3.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in Section 3.2.1.

        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display purposes
        only):

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=password&username=johndoe&password=A3ddj3w
        """
        # ignore validate for grant_type, since it is validated by
        # check_token_endpoint
        client = self.authenticate_client()

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)

        if 'username' not in self.params:
            raise InvalidRequestError(
                'Missing "username" in request.',
                uri=self.uri,
            )
        if 'password' not in self.params:
            raise InvalidRequestError(
                'Missing "password" in request.',
                uri=self.uri,
            )

        user = self.authenticate_user(
            self.params['username'],
            self.params['password']
        )
        if not user:
            raise InvalidGrantError(
                'Invalid "username" or "password" in request.',
                uri=self.uri,
            )
        self.validate_requested_scope(client)
        self._authenticated_client = client
        self._authenticated_user = user

    def create_access_token_response(self):
        """If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in Section 5.1.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in Section 5.2.

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
                "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter":"example_value"
            }

        :returns: (status_code, body, headers)
        """
        token = self.token_generator(
            self._authenticated_client, self.GRANT_TYPE,
            scope=self.params.get('scope'),
        )
        self.create_access_token(
            token,
            self._authenticated_client,
            self._authenticated_user,
        )
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

    def authenticate_user(self, username, password):
        """validate the resource owner password credentials using its
        existing password validation algorithm::

            user = get_user_by_username(username)
            if user.check_password(password):
               return user
        """
        raise NotImplementedError()

    def create_access_token(self, token, client, user):
        """Save access_token into database. Developers should implement it in
        subclass::

            def create_access_token(self, token, client, user):
                item = Token(
                    client_id=client.client_id,
                    user_id=user.id,
                    **token
                )
                item.save()

        :param token: A dict contains the token information.
        :param client: Current client related to the token.
        :param user: resource owner.
        """
        raise NotImplementedError()
