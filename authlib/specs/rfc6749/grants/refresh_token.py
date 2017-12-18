"""
    authlib.specs.rfc6749.grants.refresh_token
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6

    :copyright: (c) 2017 by Hsiaoming Yang.
    :license: LGPLv3, see LICENSE for more details.
"""

from .base import BaseGrant
from ..util import get_obj_value, scope_to_list
from ..errors import (
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError,
    InvalidClientError,
)


class RefreshTokenGrant(BaseGrant):
    """A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6
    """
    ACCESS_TOKEN_ENDPOINT = True
    GRANT_TYPE = 'refresh_token'

    def __init__(self, uri, params, headers, client_model, token_generator):
        super(RefreshTokenGrant, self).__init__(
            uri, params, headers, client_model, token_generator)
        self._authenticated_client = None
        self._authenticated_token = None

    @staticmethod
    def check_token_endpoint(params):
        return params.get('grant_type') == RefreshTokenGrant.GRANT_TYPE

    def validate_access_token_request(self):
        """If the authorization server issued a refresh token to the client, the
        client makes a refresh request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body, per Section 6:

        grant_type
             REQUIRED.  Value MUST be set to "refresh_token".

        refresh_token
             REQUIRED.  The refresh token issued to the client.

        scope
             OPTIONAL.  The scope of the access request as described by
             Section 3.3.  The requested scope MUST NOT include any scope
             not originally granted by the resource owner, and if omitted is
             treated as equal to the scope originally granted by the
             resource owner.


        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display purposes
        only):

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
        """

        # require client authentication for confidential clients or for any
        # client that was issued client credentials (or with other
        # authentication requirements)
        client = self.authenticate_client()

        if not client.check_client_type('confidential'):
            raise UnauthorizedClientError(uri=self.uri)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(uri=self.uri)

        self._authenticated_client = client

        refresh_token = self.params.get('refresh_token')
        if refresh_token is None:
            raise InvalidRequestError(
                'Missing "refresh_token" in request.',
                uri=self.uri,
            )

        token = self.authenticate_refresh_token(refresh_token)
        if not token:
            raise InvalidRequestError(
                'Invalid "refresh_token" in request.',
                uri=self.uri,
            )

        scope = self.params.get('scope')
        if scope:
            original_scope = get_obj_value(token, 'scope')
            if not original_scope:
                raise InvalidScopeError(uri=self.uri)
            original_scope = set(scope_to_list(original_scope))
            if not original_scope.issuperset(set(scope_to_list(scope))):
                raise InvalidScopeError(uri=self.uri)

        self._authenticated_token = token

    def create_access_token_response(self):
        """If valid and authorized, the authorization server issues an access
        token as described in Section 5.1.  If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in Section 5.2.
        """
        scope = self.params.get('scope')
        if not scope:
            scope = get_obj_value(self._authenticated_token, 'scope')

        expires_in = get_obj_value(self._authenticated_token, 'expires_in')
        token = self.token_generator(
            self._authenticated_client, self.GRANT_TYPE,
            expires_in=expires_in,
            scope=scope,
        )
        self.create_access_token(
            token,
            self._authenticated_client,
            self._authenticated_token
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

    def authenticate_refresh_token(self, refresh_token):
        """Get token information with refresh_token string. Developers should
        implement this method in subclass::

            def authenticate_refresh_token(self, refresh_token):
                item = Token.get(refresh_token=refresh_token)
                if item and not item.is_refresh_token_expired():
                    return item

        :param refresh_token: The refresh token issued to the client
        :return: token
        """
        raise NotImplementedError()

    def create_access_token(self, token, client, authenticated_token):
        """Save access_token into database. Developers should implement it in
        subclass::

            def create_access_token(self, token, client, authenticated_token):
                item = Token(
                    client_id=client.client_id,
                    user_id=authenticated_token.user_id,
                    **token
                )
                item.save()

        :param token: A new generated token to replace the original token.
        :param client: Current client related to the token.
        :param authenticated_token: The original token granted by resource
            owner.
        """
        raise NotImplementedError()
