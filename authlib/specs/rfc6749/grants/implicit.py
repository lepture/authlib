from authlib.common.urls import add_params_to_uri
from .base import BaseGrant
from ..errors import (
    UnauthorizedClientError,
    AccessDeniedError,
)


class ImplicitGrant(BaseGrant):
    """The implicit grant type is used to obtain access tokens (it does not
    support the issuance of refresh tokens) and is optimized for public
    clients known to operate a particular redirection URI.  These clients
    are typically implemented in a browser using a scripting language
    such as JavaScript.

    Since this is a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server.

    Unlike the authorization code grant type, in which the client makes
    separate requests for authorization and for an access token, the
    client receives the access token as the result of the authorization
    request.

    The implicit grant type does not include client authentication, and
    relies on the presence of the resource owner and the registration of
    the redirection URI.  Because the access token is encoded into the
    redirection URI, it may be exposed to the resource owner and other
    applications residing on the same device::

        +----------+
        | Resource |
        |  Owner   |
        |          |
        +----------+
             ^
             |
            (B)
        +----|-----+          Client Identifier     +---------------+
        |         -+----(A)-- & Redirection URI --->|               |
        |  User-   |                                | Authorization |
        |  Agent  -|----(B)-- User authenticates -->|     Server    |
        |          |                                |               |
        |          |<---(C)--- Redirection URI ----<|               |
        |          |          with Access Token     +---------------+
        |          |            in Fragment
        |          |                                +---------------+
        |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
        |          |          without Fragment      |     Client    |
        |          |                                |    Resource   |
        |     (F)  |<---(E)------- Script ---------<|               |
        |          |                                +---------------+
        +-|--------+
          |    |
         (A)  (G) Access Token
          |    |
          ^    v
        +---------+
        |         |
        |  Client |
        |         |
        +---------+
    """
    AUTHORIZATION_ENDPOINT = True
    GRANT_TYPE = 'implicit'

    @staticmethod
    def check_authorization_endpoint(params):
        return params.get('response_type') == 'token'

    def validate_authorization_request(self):
        """The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format.
        Per `Section 4.2.1`_.

        response_type
             REQUIRED.  Value MUST be set to "token".

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
        HTTP request using TLS::

            GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
                &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
            Host: server.example.com

        .. _`Section 4.2.1`: http://tools.ietf.org/html/rfc6749#section-4.2.1
        """
        # ignore validate for response_type, since it is validated by
        # check_authorization_endpoint
        client_id = self.params.get('client_id')
        client = self.get_and_validate_client(client_id)

        # The implicit grant type is optimized for public clients
        if not client.check_client_type('public') or \
                not client.check_response_type('token'):
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
        server issues an access token and delivers it to the client by adding
        the following parameters to the fragment component of the redirection
        URI using the "application/x-www-form-urlencoded" format.
        Per `Section 4.2.2`_.

        access_token
             REQUIRED.  The access token issued by the authorization server.

        token_type
             REQUIRED.  The type of the token issued as described in
             Section 7.1.  Value is case insensitive.

        expires_in
             RECOMMENDED.  The lifetime in seconds of the access token.  For
             example, the value "3600" denotes that the access token will
             expire in one hour from the time the response was generated.
             If omitted, the authorization server SHOULD provide the
             expiration time via other means or document the default value.

        scope
             OPTIONAL, if identical to the scope requested by the client;
             otherwise, REQUIRED.  The scope of the access token as
             described by Section 3.3.

        state
             REQUIRED if the "state" parameter was present in the client
             authorization request.  The exact value received from the
             client.

        The authorization server MUST NOT issue a refresh token.

        For example, the authorization server redirects the user-agent by
        sending the following HTTP response:

        .. code-block:: http

            HTTP/1.1 302 Found
            Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
                   &state=xyz&token_type=example&expires_in=3600

        Developers should note that some user-agents do not support the
        inclusion of a fragment component in the HTTP "Location" response
        header field.  Such clients will require using other methods for
        redirecting the client than a 3xx redirection response -- for
        example, returning an HTML page that includes a 'continue' button
        with an action linked to the redirection URI.

        .. _`Section 4.2.2`: http://tools.ietf.org/html/rfc6749#section-4.2.2

        :param grant_user: if resource owner granted the request, pass this
            resource owner's ID, otherwise pass None.
        :returns: (status_code, body, headers)
        """
        if grant_user:
            token = self.token_generator(
                self.client, self.GRANT_TYPE,
                scope=self.params.get('scope'),
                include_refresh_token=False
            )
            self.create_access_token(token, self.client, grant_user)
            params = [
                ('access_token', token['access_token']),
                ('token_type', token['token_type']),
            ]
            if 'expires_in' in token:
                params.append(('expires_in', token['expires_in']))
            if 'scope' in token:
                params.append(('scope', token['scope']))
            if self.state:
                params.append(('state', self.state))
        else:
            error = AccessDeniedError(state=self.state, uri=self.uri)
            params = error.get_body()

        uri = add_params_to_uri(self.redirect_uri, params, fragment=True)
        headers = [('Location', uri)]
        return 302, '', headers

    def create_access_token(self, token, client, grant_user):
        """Save access_token into database. Developers should implement it in
        subclass::

            def create_access_token(self, token, client, grant_user):
                item = Token(
                    client_id=client.client_id,
                    user_id=grant_user,
                    **token
                )
                item.save()

        :param token: A dict contains the token information.
        :param client: Current client related to the token.
        :param grant_user: resource owner (user) ID.
        """
        raise NotImplementedError()
