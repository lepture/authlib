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
    OAuth1Error,
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

    def validate_temporary_credentials_request(self, request):
        """Validate HTTP request for temporary credentials."""

        # The client obtains a set of temporary credentials from the server by
        # making an authenticated (Section 3) HTTP "POST" request to the
        # Temporary Credential Request endpoint (unless the server advertises
        # another HTTP request method for the client to use).
        if request.method.upper() != self.TEMPORARY_CREDENTIALS_METHOD:
            raise MethodNotAllowedError()

        # REQUIRED parameter
        if not request.client_id:
            raise MissingRequiredParameterError('oauth_consumer_key')

        # REQUIRED parameter
        oauth_callback = request.redirect_uri
        if not request.redirect_uri:
            raise MissingRequiredParameterError('oauth_callback')

        # An absolute URI or
        # other means (the parameter value MUST be set to "oob"
        if oauth_callback != 'oob' and not is_valid_url(oauth_callback):
            raise InvalidRequestError('Invalid "oauth_callback" value')

        client = self._get_client(request)
        if not client:
            raise InvalidClientError()

        self.validate_timestamp_and_nonce(request)
        self.validate_oauth_signature(request)
        return request

    def create_valid_temporary_credentials_response(
            self, method, uri, body=None, headers=None):
        """Validate temporary credentials token request and create response
        for temporary credentials token. Assume the endpoint of temporary
        credentials request is ``https://photos.example.net/initiate``:

        .. code-block:: http

            POST /initiate HTTP/1.1
            Host: photos.example.net
            Authorization: OAuth realm="Photos",
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_signature_method="HMAC-SHA1",
                oauth_timestamp="137131200",
                oauth_nonce="wIjqoS",
                oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",
                oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"

        The server validates the request and replies with a set of temporary
        credentials in the body of the HTTP response:

        .. code-block:: http

            HTTP/1.1 200 OK
            Content-Type: application/x-www-form-urlencoded

            oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&
            oauth_callback_confirmed=true

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param headers: HTTP request headers.
        :returns: (status_code, body, headers)
        """
        try:
            request = OAuth1Request(method, uri, body, headers)
            self.validate_temporary_credentials_request(request)
        except OAuth1Error as error:
            return error.status_code, error.get_body(), error.get_headers()

        token = self.create_temporary_credential(request)
        payload = [
            ('oauth_token', token.get_oauth_token()),
            ('oauth_token_secret', token.get_oauth_token_secret()),
            ('oauth_callback_confirmed', True)
        ]
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def validate_authorization_request(self, request):
        """Validate the request for resource owner authorization."""
        if not request.token:
            raise MissingRequiredParameterError('oauth_token')

        token = self.get_temporary_credential(request)
        if not token:
            raise InvalidTokenError()

        # assign token for later use
        request.credential = token
        return request

    def create_valid_authorization_response(
            self, method, uri, body=None, headers=None, grant_user=None):
        """Validate authorization request and create authorization response.
        Assume the endpoint for authorization request is
        ``https://photos.example.net/authorize``, the client redirects Jane's
        user-agent to the server's Resource Owner Authorization endpoint to
        obtain Jane's approval for accessing her private photos::

            https://photos.example.net/authorize?oauth_token=hh5s93j4hdidpola

        The server requests Jane to sign in using her username and password
        and if successful, asks her to approve granting 'printer.example.com'
        access to her private photos.  Jane approves the request and her
        user-agent is redirected to the callback URI provided by the client
        in the previous request (line breaks are for display purposes only):

            http://printer.example.com/ready?
            oauth_token=hh5s93j4hdidpola&oauth_verifier=hfdp7dh39dks9884

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param headers: HTTP request headers.
        :param grant_user: if granted, it is resource owner's ID. If denied,
            it is None.
        :returns: (status_code, body, headers)
        """
        request = OAuth1Request(method, uri, body, headers)

        # authorize endpoint should try catch this error
        self.validate_authorization_request(request)

        temporary_credentials = request.credential
        redirect_uri = temporary_credentials.get_redirect_uri()
        if not redirect_uri or redirect_uri == 'oob':
            client_id = temporary_credentials.get_client_id()
            client = self.client_model.get_by_client_id(client_id)
            redirect_uri = client.get_default_redirect_uri()

        if grant_user is None:
            error = AccessDeniedError()
            location = add_params_to_uri(redirect_uri, error.get_body())
            return 302, '', [('Location', location)]

        request.grant_user = grant_user
        verifier = self.create_authorization_verifier(request)

        params = [
            ('oauth_token', request.token),
            ('oauth_verifier', verifier)
        ]
        location = add_params_to_uri(redirect_uri, params)
        return 302, '', [('Location', location)]

    def validate_token_request(self, request):
        """Validate request for issuing token."""

        if not request.client_id:
            raise MissingRequiredParameterError('oauth_consumer_key')

        client = self._get_client(request)
        if not client:
            raise InvalidClientError()

        if not request.token:
            raise MissingRequiredParameterError('oauth_token')

        token = self.get_temporary_credential(request)
        if not token:
            raise InvalidTokenError()

        verifier = request.oauth_params.get('oauth_verifier')
        if not verifier:
            raise MissingRequiredParameterError('oauth_verifier')

        if not token.check_verifier(verifier):
            raise InvalidRequestError('Invalid "oauth_verifier"')

        request.credential = token
        self.validate_timestamp_and_nonce(request)
        self.validate_oauth_signature(request)
        return request

    def create_valid_token_response(
            self, method, uri, body=None, headers=None):
        """Validate token request and create token response. Assuming the
        endpoint of token request is ``https://photos.example.net/token``,
        the callback request informs the client that Jane completed the
        authorization process.  The client then requests a set of token
        credentials using its temporary credentials (over a secure Transport
        Layer Security (TLS) channel):

        .. code-block:: http

            POST /token HTTP/1.1
            Host: photos.example.net
            Authorization: OAuth realm="Photos",
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_token="hh5s93j4hdidpola",
                oauth_signature_method="HMAC-SHA1",
                oauth_timestamp="137131201",
                oauth_nonce="walatlh",
                oauth_verifier="hfdp7dh39dks9884",
                oauth_signature="gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D"

        The server validates the request and replies with a set of token
        credentials in the body of the HTTP response:

        .. code-block:: http

            HTTP/1.1 200 OK
            Content-Type: application/x-www-form-urlencoded

            oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00

        :param method: HTTP request method.
        :param uri: HTTP request URI string.
        :param body: HTTP request payload body.
        :param headers: HTTP request headers.
        :returns: (status_code, body, headers)
        """
        try:
            request = OAuth1Request(method, uri, body, headers)
        except OAuth1Error as error:
            # DuplicatedOAuthProtocolParameterError
            return error.status_code, error.get_body(), error.get_headers()

        try:
            self.validate_token_request(request)
        except OAuth1Error as error:
            self.delete_temporary_credential(request)
            return error.status_code, error.get_body(), error.get_headers()

        token = self.create_authorization_credential(request)
        payload = [
            ('oauth_token', token.get_oauth_token()),
            ('oauth_token_secret', token.get_oauth_token_secret()),
        ]
        self.delete_temporary_credential(request)
        return 200, payload, self.TOKEN_RESPONSE_HEADER

    def exists_nonce(self, nonce, request):
        """The nonce value MUST be unique across all requests with the same
        timestamp, client credentials, and token combinations.
        """
        raise NotImplementedError()

    def create_temporary_credential(self, request):
        raise NotImplementedError()

    def get_temporary_credential(self, request):
        raise NotImplementedError()

    def delete_temporary_credential(self, request):
        raise NotImplementedError()

    def create_authorization_verifier(self, request):
        raise NotImplementedError()

    def create_authorization_credential(self, request):
        raise NotImplementedError()
