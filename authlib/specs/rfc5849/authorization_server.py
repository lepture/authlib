import time
from authlib.common.urls import is_valid_url, add_params_to_uri
from .signature import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_RSA_SHA1,
)
from .signature import (
    verify_hmac_sha1,
    verify_plaintext,
    verify_rsa_sha1,
)
from .errors import (
    InvalidRequestError,
    InvalidSignatureError,
    AccessDeniedError,
    MethodNotAllowedError,
)
from .wrapper import OAuth1Request


class AuthorizationServer(object):
    SIGNATURE_METHODS = {
        SIGNATURE_HMAC_SHA1: verify_hmac_sha1,
        SIGNATURE_RSA_SHA1: verify_rsa_sha1,
        SIGNATURE_PLAINTEXT: verify_plaintext,
    }

    TOKEN_RESPONSE_HEADER = [
        ('Content-Type', 'application/x-www-form-urlencoded'),
        ('Cache-Control', 'no-store'),
        ('Pragma', 'no-cache'),
    ]

    TEMPORARY_CREDENTIALS_METHOD = 'POST'

    def __init__(self, client_model):
        self.client_model = client_model

    def _get_client(self, request):
        client = self.client_model.get_by_client_id(request.client_id)
        request.client = client
        return client

    @staticmethod
    def check_timestamp_and_nonce(request):
        # The parameters MAY be omitted when using the "PLAINTEXT"
        # signature method
        if request.signature_method == SIGNATURE_PLAINTEXT:
            return False

        timestamp = request.oauth_params.get('oauth_timestamp')
        nonce = request.oauth_params.get('oauth_nonce')

        if not timestamp:
            raise InvalidRequestError()
        try:
            delta = abs(time.time() - int(timestamp))
            if delta > 300:
                raise InvalidRequestError()
        except (ValueError, TypeError):
            raise InvalidRequestError()
        if not nonce:
            raise InvalidRequestError()
        return True

    def check_oauth_signature(self, request):
        if request.signature_method == SIGNATURE_RSA_SHA1:
            rsa_public_key = request.client.rsa_public_key
            return verify_rsa_sha1(request, rsa_public_key)

        verify = self.SIGNATURE_METHODS.get(request.signature_method)
        if not verify:
            raise InvalidRequestError('Invalid "oauth_signature_method"')

        if request.resource_owner_key:
            # TODO: fetch resource_owner_secret
            resource_owner_secret = None
        else:
            resource_owner_secret = None

        return verify(request, resource_owner_secret)

    def validate_oauth_signature(self, request):
        if not self.check_oauth_signature(request):
            raise InvalidSignatureError()

    def validate_temporary_credentials_request(
            self, method, uri, body=None, headers=None):
        """Validate HTTP request for temporary credentials."""

        # The client obtains a set of temporary credentials from the server by
        # making an authenticated (Section 3) HTTP "POST" request to the
        # Temporary Credential Request endpoint (unless the server advertises
        # another HTTP request method for the client to use).
        if method.upper() != self.TEMPORARY_CREDENTIALS_METHOD:
            raise MethodNotAllowedError()

        request = OAuth1Request(method, uri, body, headers)

        # REQUIRED parameter
        oauth_callback = request.oauth_params.get('oauth_callback')
        if not oauth_callback:
            raise InvalidRequestError()

        # An absolute URI or
        # other means (the parameter value MUST be set to "oob"
        if oauth_callback != 'oob' and not is_valid_url(oauth_callback):
            raise InvalidRequestError()

        if not request.client_id:
            raise InvalidRequestError()

        client = self._get_client(request)
        if not client:
            raise InvalidRequestError()

        if self.check_timestamp_and_nonce(request):
            self.validate_timestamp_and_nonce(request)

        self.validate_oauth_signature(request)
        return request

    def create_temporary_credentials_response(
            self, method, uri, body=None, headers=None):

        request = self.validate_temporary_credentials_request(
            method, uri, body, headers)
        token = self.create_temporary_credentials_token(request)
        payload = [
            ('oauth_token', token.oauth_token),
            ('oauth_token_secret', token.oauth_token_secret),
            ('oauth_callback_confirmed', True)
        ]
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def validate_resource_owner_authorization_request(
            self, method, uri, body=None, headers=None):
        """Validate
        """
        request = OAuth1Request(method, uri, body, headers)
        if not request.resource_owner_key:
            raise InvalidRequestError('Missing "oauth_token" in URI query')
        token = self.get_temporary_credentials_token(request)
        if not token:
            raise InvalidRequestError('Invalid "oauth_token" in URI query')
        request.token = token
        return request

    def create_resource_owner_authorization_response(
            self, method, uri, body=None, headers=None, grant_user=None):
        if grant_user is None:
            raise AccessDeniedError()

        request = self.validate_resource_owner_authorization_request(
            method, uri, body, headers)

        request.grant_user = grant_user
        oauth_verifier = self.create_authorization_verifier(request.token)
        oauth_callback = request.token.oauth_callback
        if not oauth_callback:
            oauth_callback = request.client.get_default_redirect_uri()
        params = [
            ('oauth_token', request.resource_owner_key),
            ('oauth_verifier', oauth_verifier)
        ]
        location = add_params_to_uri(oauth_callback, params)
        return 302, '', [('Location', location)]

    def validate_token_credentials_request(
            self, method, uri, body=None, headers=None):

        request = OAuth1Request(method, uri, body, headers)

        if not request.client_id:
            raise InvalidRequestError('Missing "oauth_consumer_key"')

        client = self._get_client(request)
        if not client:
            raise InvalidRequestError('Invalid "oauth_consumer_key"')

        if not request.resource_owner_key:
            raise InvalidRequestError('Missing "oauth_token"')

        token = self.get_temporary_credentials_token(request)
        if not token:
            raise InvalidRequestError()

        verifier = request.oauth_params.get('oauth_verifier')
        if not verifier:
            raise InvalidRequestError('Missing "oauth_verifier"')
        if token.oauth_verifier != verifier:
            raise InvalidRequestError('Invalid "oauth_verifier"')

        if self.check_timestamp_and_nonce(request):
            self.validate_timestamp_and_nonce(request)

        self.validate_oauth_signature(request)
        return request

    def create_token_credentials_response(
            self, method, uri, body=None, headers=None):

        request = self.validate_token_credentials_request(
            method, uri, body, headers)
        token = self.create_token_credentials_token(request)
        payload = [
            ('oauth_token', token.oauth_token),
            ('oauth_token_secret', token.oauth_token_secret),
        ]
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def validate_timestamp_and_nonce(self, request):
        raise NotImplementedError()

    def create_temporary_credentials_token(self, request):
        raise NotImplementedError()

    def get_temporary_credentials_token(self, request):
        raise NotImplementedError()

    def create_authorization_verifier(self, token):
        raise NotImplementedError()

    def create_token_credentials_token(self, request):
        raise NotImplementedError()
