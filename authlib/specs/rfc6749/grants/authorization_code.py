from authlib.common.urls import add_params_to_uri
from .base import BaseGrant
from ..errors import (
    UnauthorizedClientError,
    InvalidRequestError,
    InvalidScopeError,
    AccessDeniedError,
)
from ..util import scope_to_list


class AuthorizationCodeGrant(BaseGrant):
    """The authorization code grant type is used to obtain both access
    tokens and refresh tokens and is optimized for confidential clients.
    Since this is a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.

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
    (A)  (C)                                       |      |
    |    |                                         |      |
    ^    v                                         |      |
    +---------+                                    |      |
    |         |>---(D)-- Authorization Code -------'      |
    |  Client |          & Redirection URI                |
    |         |                                           |
    |         |<---(E)----- Access Token -----------------'
    +---------+       (w/ Optional Refresh Token)
    """
    AUTHORIZATION_ENDPOINT = True
    ACCESS_TOKEN_ENDPOINT = True

    @staticmethod
    def check_authorization_endpoint(params):
        return params.get('response_type') == 'code'

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == 'authorization_code'

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
        state = self.params.get('state', None)
        client = self.get_and_validate_client(client_id, state)
        if not client.check_response_type('code'):
            raise UnauthorizedClientError(
                'The client is not authorized to request an authorization '
                'code using this method',
                state=state,
                uri=self.uri,
            )

        if 'redirect_uri' in self.params:
            if not client.check_redirect_uri(self.params['redirect_uri']):
                raise InvalidRequestError(
                    'Invalid "redirect_uri" in request.',
                    state=state,
                    uri=self.uri,
                )
        elif not client.default_redirect_uri:
            raise InvalidRequestError(
                'Missing "redirect_uri" in request.'
            )

        if 'scope' in self.params:
            requested_scopes = set(scope_to_list(self.params['scope']))
            if not client.check_requested_scopes(requested_scopes):
                raise InvalidScopeError(state=state, uri=self.uri)

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

        :returns: (status_code, body, headers)
        """
        redirect_uri = self.params.get('redirect_uri')
        client = self.get_client_by_id(self.params['client_id'])
        if not redirect_uri:
            redirect_uri = client.default_redirect_uri

        state = self.params.get('state')
        if grant_user:
            code = client.create_authorization_code(grant_user, redirect_uri)
            params = [('code', code)]
            if state:
                params.append(('state', state))
        else:
            error = AccessDeniedError(state=state, uri=self.uri)
            params = error.get_body()

        uri = add_params_to_uri(redirect_uri, params)
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
        client_id, client_secret = self.parse_client_id_and_secret()

        # authenticate the client if client authentication is included
        client = self.authenticate_client(client_id, client_secret)

        code = self.params.get('code')
        if code is None:
            raise InvalidRequestError(
                'Missing "code" in request.',
                uri=self.uri,
            )

        # ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = client.parse_authorization_code(code)
        if not authorization_code:
            raise InvalidRequestError(
                'Invalid "code" in request.',
                uri=self.uri,
            )
        return authorization_code

    def create_access_token_response(self, user):
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

        :param user: create access token for the specified user.
        :returns: (status_code, body, headers)

        .. _`Section 4.1.4`: http://tools.ietf.org/html/rfc6749#section-4.1.4
        """
        client = self.get_client_by_id(self.params['client_id'])
        token = client.create_access_token(user)

        # NOTE: there is no charset for application/json, since
        # application/json should always in UTF-8.
        # The example on RFC is incorrect.
        # https://tools.ietf.org/html/rfc4627
        headers = [
            ('Content-Type', 'application/json'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache'),
        ]
        return 200, token, headers
