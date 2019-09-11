from authlib.consts import default_json_headers
from ..rfc6749 import TokenEndpoint
from ..rfc6749 import (
    InvalidRequestError,
    UnsupportedTokenTypeError,
)


class RevocationEndpoint(TokenEndpoint):
    """Implementation of revocation endpoint which is described in
    `RFC7009`_.

    .. _RFC7009: https://tools.ietf.org/html/rfc7009
    """
    #: Endpoint name to be registered
    ENDPOINT_NAME = 'revocation'

    def authenticate_endpoint_credential(self, request, client):
        """The client constructs the request by including the following
        parameters using the "application/x-www-form-urlencoded" format in
        the HTTP request entity-body:

        token
            REQUIRED.  The token that the client wants to get revoked.

        token_type_hint
            OPTIONAL.  A hint about the type of the token submitted for
            revocation.
        """
        if 'token' not in request.form:
            raise InvalidRequestError()

        token_type = request.form.get('token_type_hint')
        if token_type and token_type not in self.SUPPORTED_TOKEN_TYPES:
            raise UnsupportedTokenTypeError()
        return self.query_token(request.form['token'], token_type, client)

    def create_endpoint_response(self, request):
        """Validate revocation request and create the response for revocation.
        For example, a client may request the revocation of a refresh token
        with the following request::

            POST /revoke HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

            token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

        :returns: (status_code, body, headers)
        """
        # The authorization server first validates the client credentials
        client = self.authenticate_endpoint_client(request)

        # then verifies whether the token was issued to the client making
        # the revocation request
        credential = self.authenticate_endpoint_credential(request, client)

        # the authorization server invalidates the token
        if credential:
            self.revoke_token(credential)
            self.server.send_signal(
                'after_revoke_token',
                token=credential,
                client=client,
            )
        return 200, {}, default_json_headers

    def query_token(self, token, token_type_hint, client):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token, token_type_hint, client):
                if token_type_hint == 'access_token':
                    return Token.query_by_access_token(token, client.client_id)
                if token_type_hint == 'refresh_token':
                    return Token.query_by_refresh_token(token, client.client_id)
                return Token.query_by_access_token(token, client.client_id) or \
                    Token.query_by_refresh_token(token, client.client_id)
        """
        raise NotImplementedError()

    def revoke_token(self, token):
        """Mark token as revoked. Since token MUST be unique, it would be
        dangerous to delete it. Consider this situation:

        1. Jane obtained a token XYZ
        2. Jane revoked (deleted) token XYZ
        3. Bob generated a new token XYZ
        4. Jane can use XYZ to access Bob's resource

        It would be secure to mark a token as revoked::

            def revoke_token(self, token):
                token.revoked = True
                token.save()
        """
        raise NotImplementedError()
