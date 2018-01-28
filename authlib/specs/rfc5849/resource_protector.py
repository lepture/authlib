from .base_server import BaseServer
from .wrapper import OAuth1Request
from .errors import (
    MissingRequiredParameterError,
    InvalidClientError,
    InvalidTokenError,
)


class ResourceProtector(BaseServer):
    def validate_request(self, method, uri, body, headers):
        request = OAuth1Request(method, uri, body, headers)

        if not request.client_id:
            raise MissingRequiredParameterError('oauth_consumer_key')

        client = self.client_model.get_by_client_id(request.client_id)
        if not client:
            raise InvalidClientError()
        request.client = client

        if not request.token:
            raise MissingRequiredParameterError('oauth_token')

        token = self.get_token_credential(request)
        if not token:
            raise InvalidTokenError()

        request.credential = token
        self.validate_timestamp_and_nonce(request)
        self.validate_oauth_signature(request)
        return request

    def get_token_credential(self, request):
        raise NotImplementedError()
