import os
import time
import binascii
from authlib.consts import default_json_headers
from authlib.common.security import generate_token
from .claims import ClientMetadataClaims


class ClientRegistrationEndpoint(object):
    """The client registration endpoint is an OAuth 2.0 endpoint designed to
    allow a client to be registered with the authorization server.
    """
    ENDPOINT_NAME = 'client_registration'
    claims_class = ClientMetadataClaims

    def __init__(self, server):
        self.server = server

    def create_registration_response(self, request):
        user = self.authenticate_registration_user(request)
        client_metadata = self.extract_client_metadata(request)
        client_info = self.generate_client_info()
        body = {}
        body.update(client_metadata)
        body.update(client_info)
        self.save_client(client_info, client_metadata, user)
        return 201, body, default_json_headers

    def extract_client_metadata(self, request):
        json_data = request.data.copy()
        software_statement = json_data.pop('software_statement', None)
        if software_statement:
            data = self.extract_software_statement(software_statement, request)
            json_data.update(data)

        claims = ClientMetadataClaims(json_data, {})
        # TODO: validate claims
        return claims

    def extract_software_statement(self, software_statement, request):
        return {}

    def generate_client_info(self):
        # https://tools.ietf.org/html/rfc7591#section-3.2.1
        client_id = self.generate_client_id()
        client_secret = self.generate_client_secret()
        client_id_issued_at = int(time.time())
        client_secret_expires_at = 0
        return dict(
            client_id=client_id,
            client_secret=client_secret,
            client_id_issued_at=client_id_issued_at,
            client_secret_expires_at=client_secret_expires_at,
        )

    def generate_client_id(self):
        return generate_token(42)

    def generate_client_secret(self):
        return binascii.hexlify(os.urandom(24)).decode('ascii')

    def create_endpoint_request(self, request=None):
        raise NotImplementedError()

    def authenticate_registration_user(self, request):
        raise NotImplementedError()

    def save_client(self, client_info, client_metadata, user):
        raise NotImplementedError()
