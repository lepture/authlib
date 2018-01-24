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
    MissingRequiredParameterError,
    UnsupportedSignatureMethodError,
    InvalidClientError,
    InvalidNonceError,
    InvalidTokenError,
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
    EXPIRY_TIME = 300

    def __init__(self, client_model):
        self.client_model = client_model

    def _get_client(self, request):
        client = self.client_model.get_by_client_id(request.client_id)
        request.client = client
        return client

    def validate_timestamp_and_nonce(self, request):
        # The parameters MAY be omitted when using the "PLAINTEXT"
        # signature method
        if request.signature_method == SIGNATURE_PLAINTEXT:
            return False

        timestamp = request.oauth_params.get('oauth_timestamp')
        nonce = request.oauth_params.get('oauth_nonce')

        if not timestamp:
            raise MissingRequiredParameterError('oauth_timestamp')
        try:
            delta = time.time() - int(timestamp)
            if delta > self.EXPIRY_TIME:
                raise InvalidRequestError()
        except (ValueError, TypeError):
            raise InvalidRequestError()

        if not nonce:
            raise MissingRequiredParameterError('oauth_nonce')

        if self.exists_timestamp_and_nonce(timestamp, nonce, request):
            raise InvalidNonceError()

    def validate_oauth_signature(self, request):
        verify = self.SIGNATURE_METHODS.get(request.signature_method)
        if not verify:
            raise UnsupportedSignatureMethodError()

        if not verify(request):
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
        oauth_callback = request.redirect_uri
        if not request.redirect_uri:
            raise MissingRequiredParameterError('oauth_callback')

        # An absolute URI or
        # other means (the parameter value MUST be set to "oob"
        if oauth_callback != 'oob' and not is_valid_url(oauth_callback):
            raise InvalidRequestError()

        if not request.client_id:
            raise MissingRequiredParameterError('oauth_consumer_key')

        client = self._get_client(request)
        if not client:
            raise InvalidClientError()

        self.validate_timestamp_and_nonce(request)
        self.validate_oauth_signature(request)
        return request

    def create_temporary_credentials_response(
            self, method, uri, body=None, headers=None):

        request = self.validate_temporary_credentials_request(
            method, uri, body, headers)

        token = self.create_temporary_credentials_token(request)
        payload = [
            ('oauth_token', token.get_oauth_token()),
            ('oauth_token_secret', token.get_oauth_token_secret()),
            ('oauth_callback_confirmed', True)
        ]
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def validate_resource_owner_authorization_request(
            self, method, uri, body=None, headers=None):
        """Validate
        """
        request = OAuth1Request(method, uri, body, headers)
        if not request.resource_owner_key:
            raise MissingRequiredParameterError('oauth_token')

        token = self.get_temporary_credentials_token(request)
        if not token:
            raise InvalidTokenError()

        request.token = token
        return request

    def create_resource_owner_authorization_response(
            self, method, uri, body=None, headers=None, grant_user=None):

        if grant_user is None:
            raise AccessDeniedError()

        request = self.validate_resource_owner_authorization_request(
            method, uri, body, headers)

        request.grant_user = grant_user
        verifier = self.create_authorization_verifier(request)

        temporary_credentials = request.token
        redirect_uri = temporary_credentials.get_redirect_uri()
        if not redirect_uri:
            redirect_uri = request.client.get_default_redirect_uri()

        params = [
            ('oauth_token', request.resource_owner_key),
            ('oauth_verifier', verifier)
        ]
        location = add_params_to_uri(redirect_uri, params)
        return 302, '', [('Location', location)]

    def validate_token_credentials_request(
            self, method, uri, body=None, headers=None):

        request = OAuth1Request(method, uri, body, headers)

        if not request.client_id:
            raise MissingRequiredParameterError('oauth_consumer_key')

        client = self._get_client(request)
        if not client:
            raise InvalidClientError()

        if not request.resource_owner_key:
            raise MissingRequiredParameterError('oauth_token')

        token = self.get_temporary_credentials_token(request)
        if not token:
            raise InvalidTokenError()

        verifier = request.oauth_params.get('oauth_verifier')
        if not verifier:
            raise MissingRequiredParameterError('oauth_verifier')

        if not token.check_verifier(verifier):
            raise InvalidRequestError('Invalid "oauth_verifier"')

        request.token = token
        self.validate_timestamp_and_nonce(request)
        self.validate_oauth_signature(request)
        return request

    def create_token_credentials_response(
            self, method, uri, body=None, headers=None):

        request = self.validate_token_credentials_request(
            method, uri, body, headers)
        token = self.create_token_credentials_token(request)
        payload = [
            ('oauth_token', token.get_oauth_token()),
            ('oauth_token_secret', token.get_oauth_token_secret()),
        ]
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def exists_timestamp_and_nonce(self, timestamp, nonce, request):
        raise NotImplementedError()

    def create_temporary_credentials_token(self, request):
        raise NotImplementedError()

    def get_temporary_credentials_token(self, request):
        raise NotImplementedError()

    def create_authorization_verifier(self, request):
        raise NotImplementedError()

    def create_token_credentials_token(self, request):
        raise NotImplementedError()
