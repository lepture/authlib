import time
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
    InvalidNonceError,
    InvalidSignatureError,
)


class BaseServer(object):
    SIGNATURE_METHODS = {
        SIGNATURE_HMAC_SHA1: verify_hmac_sha1,
        SIGNATURE_RSA_SHA1: verify_rsa_sha1,
        SIGNATURE_PLAINTEXT: verify_plaintext,
    }

    EXPIRY_TIME = 300

    def __init__(self, client_model):
        self.client_model = client_model

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
            # The timestamp value MUST be a positive integer
            delta = time.time() - int(timestamp)
            if delta > self.EXPIRY_TIME:
                raise InvalidRequestError('Invalid "oauth_timestamp" value')
        except (ValueError, TypeError):
            raise InvalidRequestError('Invalid "oauth_timestamp" value')

        if not nonce:
            raise MissingRequiredParameterError('oauth_nonce')

        if self.exists_nonce(nonce, request):
            raise InvalidNonceError()

    def validate_oauth_signature(self, request):
        if not request.signature_method:
            raise MissingRequiredParameterError('oauth_signature_method')

        if not request.signature:
            raise MissingRequiredParameterError('oauth_signature')

        verify = self.SIGNATURE_METHODS.get(request.signature_method)
        if not verify:
            raise UnsupportedSignatureMethodError()

        if not verify(request):
            raise InvalidSignatureError()

    def exists_nonce(self, nonce, request):
        """The nonce value MUST be unique across all requests with the same
        timestamp, client credentials, and token combinations.
        """
        raise NotImplementedError()
