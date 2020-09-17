"""
    authlib.oauth2.rfc6749.grants.refresh_token
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6
"""

import logging
from .base import BaseGrant, TokenEndpointMixin
from ..util import scope_to_list
from ..errors import (
    InvalidRequestError,
    InvalidScopeError,
    InvalidGrantError,
    UnauthorizedClientError,
)
log = logging.getLogger(__name__)


class RefreshTokenGrant(BaseGrant, TokenEndpointMixin):
    """A special grant endpoint for refresh_token grant_type. Refreshing an
    Access Token per `Section 6`_.

    .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6
    """
    GRANT_TYPE = 'refresh_token'

    #: The authorization server MAY issue a new refresh token
    INCLUDE_NEW_REFRESH_TOKEN = False

    def _validate_request_client(self):
        # require client authentication for confidential clients or for any
        # client that was issued client credentials (or with other
        # authentication requirements)
        client = self.authenticate_token_endpoint_client()
        log.debug('Validate token request of %r', client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        return client

    def _validate_request_token(self, client):
        refresh_token = self.request.form.get('refresh_token')
        if refresh_token is None:
            raise InvalidRequestError(
                'Missing "refresh_token" in request.',
            )

        token = self.authenticate_refresh_token(refresh_token)
        if not token or token.get_client_id() != client.get_client_id():
            raise InvalidGrantError()
        return token

    def _validate_token_scope(self, token):
        scope = self.request.scope
        if not scope:
            return

        original_scope = token.get_scope()
        if not original_scope:
            raise InvalidScopeError()

        original_scope = set(scope_to_list(original_scope))
        if not original_scope.issuperset(set(scope_to_list(scope))):
            raise InvalidScopeError()

    def validate_token_request(self):
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
        client = self._validate_request_client()
        self.request.client = client
        token = self._validate_request_token(client)
        self._validate_token_scope(token)
        self.request.credential = token

    def create_token_response(self):
        """If valid and authorized, the authorization server issues an access
        token as described in Section 5.1.  If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in Section 5.2.
        """
        credential = self.request.credential
        user = self.authenticate_user(credential)
        if not user:
            raise InvalidRequestError('There is no "user" for this token.')

        client = self.request.client
        token = self.issue_token(user, credential)
        log.debug('Issue token %r to %r', token, client)

        self.request.user = user
        self.save_token(token)
        self.execute_hook('process_token', token=token)
        self.revoke_old_credential(credential)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def issue_token(self, user, credential):
        expires_in = credential.get_expires_in()
        scope = self.request.scope
        if not scope:
            scope = credential.get_scope()

        token = self.generate_token(
            user=user,
            expires_in=expires_in,
            scope=scope,
            include_refresh_token=self.INCLUDE_NEW_REFRESH_TOKEN,
        )
        return token

    def authenticate_refresh_token(self, refresh_token):
        """Get token information with refresh_token string. Developers MUST
        implement this method in subclass::

            def authenticate_refresh_token(self, refresh_token):
                item = Token.get(refresh_token=refresh_token)
                if item and item.is_refresh_token_active():
                    return item

        :param refresh_token: The refresh token issued to the client
        :return: token
        """
        raise NotImplementedError()

    def authenticate_user(self, credential):
        """Authenticate the user related to this credential. Developers MUST
        implement this method in subclass::

            def authenticate_user(self, credential):
                return User.query.get(credential.user_id)

        :param credential: Token object
        :return: user
        """
        raise NotImplementedError()

    def revoke_old_credential(self, credential):
        """The authorization server MAY revoke the old refresh token after
        issuing a new refresh token to the client. Developers MUST implement
        this method in subclass::

            def revoke_old_credential(self, credential):
                credential.revoked = True
                credential.save()

        :param credential: Token object
        """
        raise NotImplementedError()
