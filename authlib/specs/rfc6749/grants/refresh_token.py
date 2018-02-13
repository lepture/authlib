"""
    authlib.specs.rfc6749.grants.refresh_token
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6

    :copyright: (c) 2017 by Hsiaoming Yang.
    :license: LGPLv3, see LICENSE for more details.
"""

from .base import BasicAuthGrant
from ..util import scope_to_list
from ..errors import (
    InvalidRequestError,
    InvalidScopeError,
    UnauthorizedClientError,
)


class RefreshTokenGrant(BasicAuthGrant):
    """A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6
    """
    ACCESS_TOKEN_ENDPOINT = True
    GRANT_TYPE = 'refresh_token'

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
            raise UnauthorizedClientError()

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        refresh_token = self.request.data.get('refresh_token')
        if refresh_token is None:
            raise InvalidRequestError(
                'Missing "refresh_token" in request.',
            )

        token = self.authenticate_refresh_token(refresh_token)
        if not token:
            raise InvalidRequestError(
                'Invalid "refresh_token" in request.',
            )

        scope = self.request.scope
        if scope:
            original_scope = token.get_scope()
            if not original_scope:
                raise InvalidScopeError()
            original_scope = set(scope_to_list(original_scope))
            if not original_scope.issuperset(set(scope_to_list(scope))):
                raise InvalidScopeError()

        self.request.client = client
        self.request.credential = token

    def create_access_token_response(self):
        """If valid and authorized, the authorization server issues an access
        token as described in Section 5.1.  If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in Section 5.2.
        """
        scope = self.request.scope
        credential = self.request.credential
        if not scope:
            scope = credential.get_scope()

        client = self.request.client
        expires_in = credential.get_expires_in()
        token = self.token_generator(
            client, self.GRANT_TYPE,
            expires_in=expires_in,
            scope=scope,
        )
        self.create_access_token(token, client, credential)
        return 200, token, self.TOKEN_RESPONSE_HEADER

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
