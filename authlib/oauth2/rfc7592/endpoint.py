from authlib.consts import default_json_headers
from ..rfc6749 import AccessDeniedError
from ..rfc6750 import InvalidTokenError


class ClientConfigurationEndpoint(object):
    ENDPOINT_NAME = 'client_configuration'

    def __init__(self, server):
        self.server = server

    def __call__(self, request):
        return self.create_configuration_response(request)

    def create_configuration_response(self, request):
        token = self.authenticate_token(request)
        if not token:
            raise InvalidTokenError()

        request.credential = token

        client = self.authenticate_client(request)
        if not client:
            # If the client does not exist on this server, the server MUST respond
            # with HTTP 401 Unauthorized and the registration access token used to
            # make this request SHOULD be immediately revoked.
            self.revoke_access_token(request)
            raise InvalidTokenError()

        if not self.check_permission(client, request):
            # If the client does not have permission to read its record, the server
            # MUST return an HTTP 403 Forbidden.
            raise AccessDeniedError()

        request.client = client

        if request.method == 'GET':
            return self.create_read_client_response(client, request)
        elif request.method == 'DELETE':
            return self.create_delete_client_response(client, request)
        elif request.method == 'PUT':
            return self.create_update_client_response(client, request)

    def create_endpoint_request(self, request):
        return self.server.create_json_request(request)

    def create_read_client_response(self, client, request):
        body = self.introspect_client(client)
        info = self.generate_client_registration_info(client, request)
        body.update(info)
        return 200, body, default_json_headers

    def create_delete_client_response(self, client, request):
        """To deprive itself on the authorization server, the client makes
        an HTTP DELETE request to the client configuration endpoint.  This
        request is authenticated by the registration access token issued to
        the client.

        The following is a non-normative example request::

            DELETE /register/s6BhdRkqt3 HTTP/1.1
            Host: server.example.com
            Authorization: Bearer reg-23410913-abewfq.123483
        """
        self.delete_client(client, request)
        headers = [
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache'),
        ]
        return 204, '', headers

    def create_update_client_response(self, client, request):
        """ To update a previously registered client's registration with an
        authorization server, the client makes an HTTP PUT request to the
        client configuration endpoint with a content type of "application/
        json".

        The following is a non-normative example request::

            PUT /register/s6BhdRkqt3 HTTP/1.1
            Accept: application/json
            Host: server.example.com
            Authorization: Bearer reg-23410913-abewfq.123483

            {
                "client_id": "s6BhdRkqt3",
                "client_secret": "cf136dc3c1fc93f31185e5885805d",
                "redirect_uris": [
                    "https://client.example.org/callback",
                    "https://client.example.org/alt"
                ],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_basic",
                "jwks_uri": "https://client.example.org/my_public_keys.jwks",
                "client_name": "My New Example",
                "client_name#fr": "Mon Nouvel Exemple",
                "logo_uri": "https://client.example.org/newlogo.png",
                "logo_uri#fr": "https://client.example.org/fr/newlogo.png"
            }
        """
        # The updated client metadata fields request MUST NOT include the
        # "registration_access_token", "registration_client_uri",
        # "client_secret_expires_at", or "client_id_issued_at" fields
        must_not_include = (
            'registration_access_token', 'registration_client_uri',
            'client_secret_expires_at', 'client_id_issued_at',
        )
        for k in must_not_include:
            if k in request.data:
                return

        # The client MUST include its "client_id" field in the request
        client_id = request.data.get('client_id')
        if not client_id:
            raise
        if client_id != client.get_client_id():
            raise

        # If the client includes the "client_secret" field in the request,
        # the value of this field MUST match the currently issued client
        # secret for that client.
        if 'client_secret' in request.data:
            if not client.check_client_secret(request.data['client_secret']):
                raise

        client = self.save_client(client, request)
        return self.create_read_client_response(client, request)

    def generate_client_registration_info(self, client, request):
        """Generate ```registration_client_uri`` and ``registration_access_token``
        for RFC7592. This method returns ``None`` by default. Developers MAY rewrite
        this method to return registration information."""
        raise NotImplementedError()

    def authenticate_token(self, request):
        """Authenticate current credential who is requesting to register a client.
        Developers MUST implement this method in subclass::

            def authenticate_token(self, request):
                auth = request.headers.get('Authorization')
                return get_token_by_auth(auth)

        :return: token instance
        """
        raise NotImplementedError()

    def authenticate_client(self, request):
        raise NotImplementedError()

    def revoke_access_token(self, request):
        raise NotImplementedError()

    def check_permission(self, client, request):
        raise NotImplementedError()

    def introspect_client(self, client):
        raise NotImplementedError()

    def delete_client(self, client, request):
        """Delete authorization code from database or cache. Developers MUST
        implement it in subclass, e.g.::

            def delete_client(self, client, request):
                client.delete()

        :param client: the instance of OAuth client
        :param request: formatted request instance
        """
        raise NotImplementedError()

    def save_client(self, client, request):
        raise NotImplementedError()
