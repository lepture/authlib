import time
import logging
from ..rfc6749.errors import (
    InvalidRequestError,
    UnauthorizedClientError,
    AccessDeniedError,
)
from ..rfc6749.grants import BaseGrant, TokenEndpointMixin
from .errors import (
    AuthorizationPendingError,
    ExpiredTokenError,
    SlowDownError,
)

log = logging.getLogger(__name__)
DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'


class DeviceCodeGrant(BaseGrant, TokenEndpointMixin):
    TOKEN_ENDPOINT_AUTH_METHODS = ['none']
    GRANT_TYPE = DEVICE_CODE_GRANT_TYPE
    #: The authorization server MAY contain a refresh token
    INCLUDE_REFRESH_TOKEN = False

    def validate_token_request(self):
        """After displaying instructions to the user, the client creates an
        access token request and sends it to the token endpoint with the
        following parameters:

        grant_type
            REQUIRED.  Value MUST be set to
            "urn:ietf:params:oauth:grant-type:device_code".

        device_code
            REQUIRED.  The device verification code, "device_code" from the
            device authorization response.

        client_id
            REQUIRED if the client is not authenticating with the
            authorization server as described in Section 3.2.1. of [RFC6749].
            The client identifier as described in Section 2.2 of [RFC6749].

        For example, the client makes the following HTTPS request::

            POST /token HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
            &device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
            &client_id=1406020730
        """
        device_code = self.request.data.get('device_code')
        if not device_code:
            raise InvalidRequestError('Missing "device_code"')

        if not self.request.client_id:
            raise InvalidRequestError('Missing "client_id"')

        credential = self.query_device_credential(device_code)
        if not credential:
            raise InvalidRequestError('Invalid "device_code"')

        if credential.get_client_id() != self.request.client_id:
            raise UnauthorizedClientError()

        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        user = self.validate_device_credential(credential)
        self.request.user = user
        self.request.client = client
        self.request.credential = credential

    def create_token_response(self):
        client = self.request.client
        scope = self.request.credential.get_scope()
        token = self.generate_token(
            client, self.GRANT_TYPE,
            user=self.request.user,
            scope=client.get_allowed_scope(scope),
            include_refresh_token=self.INCLUDE_REFRESH_TOKEN,
        )
        log.debug('Issue token %r to %r', token, client)
        self.save_token(token)
        self.execute_hook('process_token', token=token)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def validate_device_credential(self, credential):
        user_code = credential.get_user_code()
        user_grant = self.query_user_grant(user_code)

        if user_grant is not None:
            user_id, approved = user_grant
            if not approved:
                raise AccessDeniedError()
            user = self.authenticate_user(user_id)
            return user

        exp = credential.get_expires_at()
        now = time.time()
        if exp < now:
            raise ExpiredTokenError()

        if self.should_slow_down(credential, now):
            raise SlowDownError()

        raise AuthorizationPendingError()

    def query_device_credential(self, device_code):
        raise NotImplementedError()

    def query_user_grant(self, user_code):
        raise NotImplementedError()

    def authenticate_user(self, user_id):
        raise NotImplementedError()

    def should_slow_down(self, credential, now):
        """The authorization request is still pending and polling should
        continue, but the interval MUST be increased by 5 seconds for this
        and all subsequent requests.
        """
        raise NotImplementedError()
