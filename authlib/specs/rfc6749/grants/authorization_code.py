from authlib.common.urls import add_params_to_uri
from .base import BaseGrant
from ..util import get_obj_value
from ..errors import (
    UnauthorizedClientError,
    InvalidRequestError,
    InvalidClientError,
    AccessDeniedError,
)


class AuthorizationCodeGrant(BaseGrant):
    """The authorization code grant type is used to obtain both access
    tokens and refresh tokens and is optimized for confidential clients.
    Since this is a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server::

        +----------+
        | Resource |
        |   Owner  |
        |          |
        +----------+
             ^
             |
            (B)
        +----|-----+          Client Identifier      +---------------+
        |         -+----(A)-- & Redirection URI ---->|               |
        |  User-   |                                 | Authorization |
        |  Agent  -+----(B)-- User authenticates --->|     Server    |
        |          |                                 |               |
        |         -+----(C)-- Authorization Code ---<|               |
        +-|----|---+                                 +---------------+
          |    |                                         ^      v
         (A)  (C)                                        |      |
          |    |                                         |      |
          ^    v                                         |      |
        +---------+                                      |      |
        |         |>---(D)-- Authorization Code ---------'      |
        |  Client |          & Redirection URI                  |
        |         |                                             |
        |         |<---(E)----- Access Token -------------------'
        +---------+       (w/ Optional Refresh Token)
    """
    AUTHORIZATION_ENDPOINT = True
    ACCESS_TOKEN_ENDPOINT = True
    GRANT_TYPE = 'authorization_code'

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(AuthorizationCodeGrant, self).__init__(
            uri, params, headers, client_model, token_generator)
        self._authenticated_client = None
        self._authorization_code = None

    @staticmethod
    def check_authorization_endpoint(params):
        return params.get('response_type') == 'code'

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == AuthorizationCodeGrant.GRANT_TYPE

    def validate_authorization_request(self):
        """The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format.
        Per `Section 4.1.1`_.

        response_type
             REQUIRED.  Value MUST be set to "code".

        client_id
            REQUIRED.  The client identifier as described in Section 2.2.

        redirect_uri
            OPTIONAL.  As described in Section 3.1.2.

        scope
            OPTIONAL.  The scope of the access request as described by
            Section 3.3.

        state
             RECOMMENDED.  An opaque value used by the client to maintain
             state between the request and callback.  The authorization
             server includes this value when redirecting the user-agent back
             to the client.  The parameter SHOULD be used for preventing
             cross-site request forgery as described in Section 10.12.

        The client directs the resource owner to the constructed URI using an
        HTTP redirection response, or by other means available to it via the
        user-agent.

        For example, the client directs the user-agent to make the following
        HTTP request using TLS (with extra line breaks for display purposes
        only)::

            GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
                &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
            Host: server.example.com

        The authorization server validates the request to ensure that all
        required parameters are present and valid.  If the request is valid,
        the authorization server authenticates the resource owner and obtains
        an authorization decision (by asking the resource owner or by
        establishing approval via other means).

        .. _`Section 4.1.1`: http://tools.ietf.org/html/rfc6749#section-4.1.1
        """
        # ignore validate for response_type, since it is validated by
        # check_authorization_endpoint
        client_id = self.params.get('client_id')
        client = self.get_and_validate_client(client_id)
        if not client.check_response_type('code'):
            raise UnauthorizedClientError(
                'The client is not authorized to request an authorization '
                'code using this method',
                state=self.state,
                uri=self.uri,
            )

        self.validate_authorization_redirect_uri(client)
        self.validate_requested_scope(client)

    def create_authorization_response(self, grant_user):
        """If the resource owner grants the access request, the authorization
        server issues an authorization code and delivers it to the client by
        adding the following parameters to the query component of the
        redirection URI using the "application/x-www-form-urlencoded" format.
        Per `Section 4.1.2`_.

        code
            REQUIRED.  The authorization code generated by the
            authorization server. The authorization code MUST expire
            shortly after it is issued to mitigate the risk of leaks. A
            maximum authorization code lifetime of 10 minutes is
            RECOMMENDED. The client MUST NOT use the authorization code
            more than once. If an authorization code is used more than
            once, the authorization server MUST deny the request and SHOULD
            revoke (when possible) all tokens previously issued based on
            that authorization code.  The authorization code is bound to
            the client identifier and redirection URI.
        state
            REQUIRED if the "state" parameter was present in the client
            authorization request.  The exact value received from the
            client.

        For example, the authorization server redirects the user-agent by
        sending the following HTTP response.

        .. code-block:: http

            HTTP/1.1 302 Found
            Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
                   &state=xyz

        .. _`Section 4.1.2`: http://tools.ietf.org/html/rfc6749#section-4.1.2

        :param grant_user: if resource owner granted the request, pass this
            resource owner's ID, otherwise pass None.
        :returns: (status_code, body, headers)
        """
        if grant_user:
            code = self.create_authorization_code(
                self.client, grant_user, **self.params)
            params = [('code', code)]
            if self.state:
                params.append(('state', self.state))
        else:
            error = AccessDeniedError(state=self.state, uri=self.uri)
            params = error.get_body()

        uri = add_params_to_uri(self.redirect_uri, params)
        headers = [('Location', uri)]
        return 302, '', headers

    def validate_access_token_request(self):
        """The client makes a request to the token endpoint by sending the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body, per `Section 4.1.3`_:

        grant_type
             REQUIRED.  Value MUST be set to "authorization_code".

        code
             REQUIRED.  The authorization code received from the
             authorization server.

        redirect_uri
             REQUIRED, if the "redirect_uri" parameter was included in the
             authorization request as described in Section 4.1.1, and their
             values MUST be identical.

        client_id
             REQUIRED, if the client is not authenticating with the
             authorization server as described in Section 3.2.1.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in Section 3.2.1.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        # ignore validate for grant_type, since it is validated by
        # check_token_endpoint

        # authenticate the client if client authentication is included
        client = self.authenticate_client()

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)

        code = self.params.get('code')
        if code is None:
            raise InvalidRequestError(
                'Missing "code" in request.',
                uri=self.uri,
            )

        # ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = self.parse_authorization_code(code, client)
        if not authorization_code:
            raise InvalidRequestError(
                'Invalid "code" in request.',
                uri=self.uri,
            )

        # validate redirect_uri parameter
        redirect_uri = self.params.get('redirect_uri')
        _redirect_uri = get_obj_value(authorization_code, 'redirect_uri')
        original_redirect_uri = _redirect_uri or None
        if redirect_uri != original_redirect_uri:
            raise InvalidRequestError(
                'Invalid "redirect_uri" in request.',
                uri=self.uri,
            )

        # save for create_access_token_response
        self._authenticated_client = client
        self._authorization_code = authorization_code

    def create_access_token_response(self):
        """If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in Section 5.1.  If the request client
        authentication failed or is invalid, the authorization server returns
        an error response as described in Section 5.2. Per `Section 4.1.4`_.

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

        .. _`Section 4.1.4`: http://tools.ietf.org/html/rfc6749#section-4.1.4
        """
        client = self._authenticated_client
        is_confidential = client.check_client_type('confidential')
        token = self.token_generator(
            client,
            self.GRANT_TYPE,
            scope=get_obj_value(self._authorization_code, 'scope'),
            include_refresh_token=is_confidential,
        )
        self.create_access_token(
            token,
            client,
            self._authorization_code
        )
        self.delete_authorization_code(self._authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def authenticate_client(self):
        """Parse the authenticated client.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        To authenticate client with other means, re-implement this method in
        subclass.

        :return: client
        """
        client_params = self.parse_basic_auth_header()
        if client_params:
            # authenticate the client if client authentication is included
            client_id, client_secret = client_params
            client = self.get_and_validate_client(client_id)
            if client_secret != client.client_secret:
                raise InvalidClientError(uri=self.uri)

            return client

        # require client authentication for confidential clients or for any
        # client that was issued client credentials (or with other
        # authentication requirements)
        client_id = self.params.get('client_id')
        client = self.get_and_validate_client(client_id)
        if client.check_client_type('confidential') or client.client_secret:
            raise UnauthorizedClientError(uri=self.uri)

        return client

    def create_authorization_code(self, client, grant_user, **kwargs):
        """Save authorization_code for later use. Developers should implement
        it in subclass. Here is an example::

            from authlib.common.security import generate_token

            def create_authorization_code(self, client, grant_user, **kwargs):
                code = generate_token(48)
                item = AuthorizationCode(
                    code=code,
                    client_id=client.client_id,
                    redirect_uri=kwargs.get('redirect_uri', ''),
                    scope=kwargs.get('scope', ''),
                    user_id=grant_user,
                )
                item.save()
                return code

        :param client: the client that requesting the token.
        :param grant_user: resource owner (user) ID.
        :param kwargs: other parameters.
        :return: code string
        """
        raise NotImplementedError()

    def parse_authorization_code(self, code, client):
        """Get authorization_code from previously savings. Developers should
        implement it in subclass::

            def parse_authorization_code(self, code, client):
                return Authorization.get(code=code, client_id=client.client_id)

        :param code: a string represent the code.
        :param client: client related to this code.
        :return: authorization_code object
        """
        raise NotImplementedError()

    def delete_authorization_code(self, authorization_code):
        """Delete authorization code from database or cache. Developers should
        implement it in subclass::

            def delete_authorization_code(self, authorization_code):
                authorization_code.delete()

        :param authorization_code: the instance of authorization_code
        """
        raise NotImplementedError()

    def create_access_token(self, token, client, authorization_code):
        """Save access_token into database. Developers should implement it in
        subclass::

            def create_access_token(self, token, client, authorization_code):
                item = Token(
                    client_id=client.client_id,
                    user_id=authorization_code.user_id,
                    **token
                )
                item.save()
                # if you want to add extra data into token
                token['user_id'] = authorization_code.user_id

        :param token: A dict contains the token information
        :param client: Current client related to the token
        :param authorization_code: previously saved authorization_code
        """
        raise NotImplementedError()
