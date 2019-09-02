from authlib.oauth2.rfc7009 import RevocationEndpoint as _RevocationEndpoint


class RevocationEndpoint(_RevocationEndpoint):
    """The revocation endpoint for OAuth authorization servers allows clients
    to notify the authorization server that a previously obtained refresh or
    access token is no longer needed.

    Register it into authorization server, and create token endpoint response
    for token revocation::

        from django.views.decorators.http import require_http_methods

        # see register into authorization server instance
        server.register_endpoint(RevocationEndpoint)

        @require_http_methods(["POST"])
        def revoke_token(request):
            return server.create_endpoint_response(
                RevocationEndpoint.ENDPOINT_NAME,
                request
            )
    """

    def query_token(self, token, token_type_hint, client):
        """Query requested token from database."""
        client_id = client.get_client_id()
        token_model = self.server.token_model
        if token_type_hint == 'access_token':
            try:
                return token_model.objects.get(
                    access_token=token, client_id=client_id)
            except token_model.DoesNotExist:
                return None

        if token_type_hint == 'refresh_token':
            try:
                return token_model.objects.get(
                    refresh_token=token, client_id=client_id)
            except token_model.DoesNotExist:
                return None

        try:
            return token_model.objects.get(
                access_token=token, client_id=client_id)
        except token_model.DoesNotExist:
            try:
                return token_model.objects.get(
                    refresh_token=token, client_id=client_id)
            except token_model.DoesNotExist:
                return None

    def revoke_token(self, token):
        """Mark the give token as revoked."""
        token.revoked = True
        token.save()
