import hashlib
from authlib.common.encoding import to_native, urlsafe_b64encode
from ..rfc6749.grants import AuthorizationCodeGrant as _CodeGrant
from ..rfc6749.errors import InvalidRequestError, InvalidGrantError


def validate_plain_code_challenge(code_verifier, code_challenge):
    # If the "code_challenge_method" from Section 4.3 was "plain",
    # they are compared directly
    return code_verifier == code_challenge


def validate_s256_code_challenge(code_verifier, code_challenge):
    # BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
    data = hashlib.sha256(to_native(code_verifier)).digest()
    return urlsafe_b64encode(data) == code_challenge


class AuthorizationCodeGrant(_CodeGrant):
    #: defaults to "plain" if not present in the request
    DEFAULT_CODE_CHALLENGE_METHOD = 'plain'
    SUPPORTED_CODE_CHALLENGE_METHOD = ['plain', 'S256']

    CHALLENGE_METHODS = {
        'plain': validate_plain_code_challenge,
        'S256': validate_s256_code_challenge,
    }

    def validate_authorization_request(self):
        super(AuthorizationCodeGrant, self).validate_authorization_request()

        client = self.request.client
        challenge = self.request.data.get('code_challenge')
        if not client.has_client_secret() and not challenge:
            raise InvalidRequestError('Missing "code_challenge"')

    def validate_token_request(self):
        super(AuthorizationCodeGrant, self).validate_token_request()

        verifier = self.request.data.get('code_verifier')
        client = self.request.client

        # public client MUST verify code challenge
        if not client.has_client_secret() and not verifier:
            raise InvalidRequestError('Missing "code_verifier"')

        authorization_code = self.request.credential
        challenge = self.get_authorization_code_challenge(authorization_code)

        # ignore, it is the normal RFC6749 authorization_code request
        if challenge is None and verifier is None:
            return

        if not verifier:
            raise InvalidRequestError('Missing "code_verifier"')

        # 4.6. Server Verifies code_verifier before Returning the Tokens
        method = self.get_authorization_code_challenge_method(authorization_code)
        if method is None:
            # default method is "plain"
            method = 'plain'

        if method not in self.SUPPORTED_CODE_CHALLENGE_METHOD:
            raise InvalidRequestError(
                description='Invalid "code_challenge_method"')

        func = self.CHALLENGE_METHODS.get(method)
        if not func:
            raise RuntimeError('No verify method for "{}"'.format(method))

        # If the values are not equal, an error response indicating
        # "invalid_grant" MUST be returned.
        if not func(verifier, challenge):
            raise InvalidGrantError(description='Code challenge failed.')

    def get_authorization_code_challenge(self, authorization_code):
        raise NotImplementedError()

    def get_authorization_code_challenge_method(self, authorization_code):
        raise NotImplementedError()
