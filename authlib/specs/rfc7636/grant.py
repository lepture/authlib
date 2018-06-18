from ..rfc6749.grants import AuthorizationCodeGrant as _CodeGrant
from ..rfc6749.errors import InvalidRequestError, InvalidGrantError
from .challenge import (
    compare_plain_code_challenge,
    compare_s256_code_challenge
)


class AuthorizationCodeGrant(_CodeGrant):
    #: defaults to "plain" if not present in the request
    DEFAULT_CODE_CHALLENGE_METHOD = 'plain'
    SUPPORTED_CODE_CHALLENGE_METHOD = ['plain', 'S256']

    CODE_CHALLENGE_METHODS = {
        'plain': compare_plain_code_challenge,
        'S256': compare_s256_code_challenge,
    }

    def validate_authorization_request(self):
        super(AuthorizationCodeGrant, self).validate_authorization_request()
        self.validate_code_challenge()

    def validate_token_request(self):
        super(AuthorizationCodeGrant, self).validate_token_request()
        self.validate_code_verifier()

    def validate_code_challenge(self):
        client = self.request.client
        challenge = self.request.data.get('code_challenge')
        if not client.has_client_secret() and not challenge:
            raise InvalidRequestError('Missing "code_challenge"')

        method = self.request.data.get('code_challenge_method')
        if method and method not in self.SUPPORTED_CODE_CHALLENGE_METHOD:
            raise InvalidRequestError(
                description='Unsupported "code_challenge_method"')

    def validate_code_verifier(self):
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
            method = self.DEFAULT_CODE_CHALLENGE_METHOD

        func = self.CODE_CHALLENGE_METHODS.get(method)
        if not func:
            raise RuntimeError('No verify method for "{}"'.format(method))

        # If the values are not equal, an error response indicating
        # "invalid_grant" MUST be returned.
        if not func(verifier, challenge):
            raise InvalidGrantError(description='Code challenge failed.')

    def get_authorization_code_challenge(self, authorization_code):
        """Get "code_challenge" associated with this authorization code.
        Developers MUST implement it in subclass, e.g.::

            def get_authorization_code_challenge(self, authorization_code):
                return authorization_code.code_challenge

        :param authorization_code: the instance of authorization_code
        """
        raise NotImplementedError()

    def get_authorization_code_challenge_method(self, authorization_code):
        """Get "code_challenge_method" associated with this authorization code.
        Developers MUST implement it in subclass, e.g.::

            def get_authorization_code_challenge_method(self, authorization_code):
                return authorization_code.code_challenge_method

        :param authorization_code: the instance of authorization_code
        """
        raise NotImplementedError()
