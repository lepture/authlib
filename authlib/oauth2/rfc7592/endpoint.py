from authlib.consts import default_json_headers
from authlib.jose import JoseError
from ..rfc7591.claims import ClientMetadataClaims
from ..rfc6749 import scope_to_list
from ..rfc6749 import AccessDeniedError
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import UnauthorizedClientError
from ..rfc7591 import InvalidClientMetadataError


class ClientConfigurationEndpoint:
    ENDPOINT_NAME = 'client_configuration'

    #: The claims validation class
    claims_class = ClientMetadataClaims

    def __init__(self, server):
        self.server = server

    def __call__(self, request):
        return self.create_configuration_response(request)

    def create_configuration_response(self, request):
        # This request is authenticated by the registration access token issued
        # to the client.
        token = self.authenticate_token(request)
        if not token:
            raise AccessDeniedError()

        request.credential = token

        client = self.authenticate_client(request)
        if not client:
            # If the client does not exist on this server, the server MUST respond
            # with HTTP 401 Unauthorized and the registration access token used to
            # make this request SHOULD be immediately revoked.
            self.revoke_access_token(request, token)
            raise InvalidClientError(status_code=401)

        if not self.check_permission(client, request):
            # If the client does not have permission to read its record, the server
            # MUST return an HTTP 403 Forbidden.
            raise UnauthorizedClientError(status_code=403)

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
        body.update(self.generate_client_registration_info(client, request))
        return 200, body, default_json_headers

    def create_delete_client_response(self, client, request):
        self.delete_client(client, request)
        headers = [
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache'),
        ]
        return 204, '', headers

    def create_update_client_response(self, client, request):
        # The updated client metadata fields request MUST NOT include the
        # 'registration_access_token', 'registration_client_uri',
        # 'client_secret_expires_at', or 'client_id_issued_at' fields
        must_not_include = (
            'registration_access_token',
            'registration_client_uri',
            'client_secret_expires_at',
            'client_id_issued_at',
        )
        for k in must_not_include:
            if k in request.data:
                raise InvalidRequestError()

        # The client MUST include its 'client_id' field in the request
        client_id = request.data.get('client_id')
        if not client_id:
            raise InvalidRequestError()
        if client_id != client.get_client_id():
            raise InvalidRequestError()

        # If the client includes the 'client_secret' field in the request,
        # the value of this field MUST match the currently issued client
        # secret for that client.
        if 'client_secret' in request.data:
            if not client.check_client_secret(request.data['client_secret']):
                raise InvalidRequestError()

        client_metadata = self.extract_client_metadata(request)
        client = self.update_client(client, client_metadata, request)
        return self.create_read_client_response(client, request)

    def extract_client_metadata(self, request):
        json_data = request.data.copy()
        options = self.get_claims_options()
        claims = self.claims_class(json_data, {}, options, self.get_server_metadata())

        try:
            claims.validate()
        except JoseError as error:
            raise InvalidClientMetadataError(error.description)
        return claims.get_registered_claims()

    def get_claims_options(self):
        metadata = self.get_server_metadata()
        if not metadata:
            return {}

        scopes_supported = metadata.get('scopes_supported')
        response_types_supported = metadata.get('response_types_supported')
        grant_types_supported = metadata.get('grant_types_supported')
        auth_methods_supported = metadata.get('token_endpoint_auth_methods_supported')
        options = {}
        if scopes_supported is not None:
            scopes_supported = set(scopes_supported)

            def _validate_scope(claims, value):
                if not value:
                    return True
                scopes = set(scope_to_list(value))
                return scopes_supported.issuperset(scopes)

            options['scope'] = {'validate': _validate_scope}

        if response_types_supported is not None:
            response_types_supported = set(response_types_supported)

            def _validate_response_types(claims, value):
                # If omitted, the default is that the client will use only the "code"
                # response type.
                response_types = set(value) if value else {"code"}
                return response_types_supported.issuperset(response_types)

            options['response_types'] = {'validate': _validate_response_types}

        if grant_types_supported is not None:
            grant_types_supported = set(grant_types_supported)

            def _validate_grant_types(claims, value):
                # If omitted, the default behavior is that the client will use only
                # the "authorization_code" Grant Type.
                grant_types = set(value) if value else {"authorization_code"}
                return grant_types_supported.issuperset(grant_types)

            options['grant_types'] = {'validate': _validate_grant_types}

        if auth_methods_supported is not None:
            options['token_endpoint_auth_method'] = {'values': auth_methods_supported}

        return options

    def introspect_client(self, client):
        return {**client.client_info, **client.client_metadata}

    def generate_client_registration_info(self, client, request):
        """Generate ```registration_client_uri`` and ``registration_access_token``
        for RFC7592. By default this method returns the values sent in the current
        request. Developers MUST rewrite this method to return different registration
        information.::

            def generate_client_registration_info(self, client, request):{
                access_token = request.headers['Authorization'].split(' ')[1]
                return {
                    'registration_client_uri': request.uri,
                    'registration_access_token': access_token,
                }

        :param client: the instance of OAuth client
        :param request: formatted request instance
        """
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
        """Read a client from the request payload.
        Developers MUST implement this method in subclass::

            def authenticate_client(self, request):
                client_id = request.data.get('client_id')
                return Client.get(client_id=client_id)

        :return: client instance
        """
        raise NotImplementedError()

    def revoke_access_token(self, token, request):
        """Revoke a token access in case an invalid client has been requested.
        Developers MUST implement this method in subclass::

            def revoke_access_token(self, token, request):
                token.revoked = True
                token.save()

        """
        raise NotImplementedError()

    def check_permission(self, client, request):
        """Checks wether the current client is allowed to be accessed, edited
        or deleted. Developers MUST implement it in subclass, e.g.::

            def check_permission(self, client, request):
                return client.editable

        :return: boolean
        """
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

    def update_client(self, client, client_metadata, request):
        """Update the client in the database. Developers MUST implement this method
        in subclass::

            def update_client(self, client, client_metadata, request):
                client.set_client_metadata({**client.client_metadata, **client_metadata})
                client.save()
                return client

        :param client: the instance of OAuth client
        :param client_metadata: a dict of the client claims to update
        :param request: formatted request instance
        :return: client instance
        """

        raise NotImplementedError()

    def get_server_metadata(self):
        """Return server metadata which includes supported grant types,
        response types and etc.
        """
        raise NotImplementedError()
