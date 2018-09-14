from ..rfc6749.grants import AuthorizationCodeGrant as _CodeGrant
from ..rfc6749.errors import InvalidRequestError, InvalidGrantError
from .challenge import (
    compare_plain_code_challenge,
    compare_s256_code_challenge
)


class AuthorizationCodeGrant(_CodeGrant):
    def __init__(self, *args, **kwargs):
        super(AuthorizationCodeGrant, self).__init__(*args, **kwargs)
        challenge = CodeChallenge(required=True)
        challenge.get_authorization_code_challenge = self.get_authorization_code_challenge
        challenge.get_authorization_code_challenge_method = self.get_authorization_code_challenge_method
        self.challenge = challenge

    def validate_authorization_request(self):
        super(AuthorizationCodeGrant, self).validate_authorization_request()
        self.challenge.validate_code_challenge(self)

    def validate_token_request(self):
        super(AuthorizationCodeGrant, self).validate_token_request()
        self.challenge.validate_code_verifier(self)

    def get_authorization_code_challenge(self, authorization_code):
        raise NotImplementedError()

    def get_authorization_code_challenge_method(self, authorization_code):
        raise NotImplementedError()


class CodeChallenge(object):
    """CodeChallenge extension to Authorization Code Grant. It is used to
    improve the security of Authorization Code flow for public clients by
    sending extra "code_challenge" and "code_verifier" to the authorization
    server.

    The AuthorizationCodeGrant SHOULD save the code_challenge and
    code_challenge_method into database when create_authorization_code. Then
    register this extension via::

        server.register_grant(
            AuthorizationCodeGrant,
            [CodeChallenge(required=True)]
        )
    """
    #: defaults to "plain" if not present in the request
    DEFAULT_CODE_CHALLENGE_METHOD = 'plain'
    #: supported ``code_challenge_method``
    SUPPORTED_CODE_CHALLENGE_METHOD = ['plain', 'S256']

    CODE_CHALLENGE_METHODS = {
        'plain': compare_plain_code_challenge,
        'S256': compare_s256_code_challenge,
    }

    def __init__(self, required=False):
        self.required = required

    def __call__(self, grant):
        grant.register_hook(
            'after_validate_authorization_request',
            self.validate_code_challenge,
        )
        grant.register_hook(
            'after_validate_token_request',
            self.validate_code_verifier,
        )

    def validate_code_challenge(self, grant):
        challenge = grant.request.data.get('code_challenge')
        method = grant.request.data.get('code_challenge_method')
        if not self.required and not challenge and not method:
            return

        client = grant.request.client
        if not client.has_client_secret() and not challenge:
            raise InvalidRequestError('Missing "code_challenge"')

        if method and method not in self.SUPPORTED_CODE_CHALLENGE_METHOD:
            raise InvalidRequestError(
                description='Unsupported "code_challenge_method"')

    def validate_code_verifier(self, grant):
        verifier = grant.request.data.get('code_verifier')
        client = grant.request.client

        # public client MUST verify code challenge
        if self.required and not client.has_client_secret() and not verifier:
            raise InvalidRequestError('Missing "code_verifier"')

        authorization_code = grant.request.credential
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
        Developers CAN re-implement it in subclass, the default logic::

            def get_authorization_code_challenge(self, authorization_code):
                return authorization_code.code_challenge

        :param authorization_code: the instance of authorization_code
        """
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        """Get "code_challenge_method" associated with this authorization code.
        Developers CAN re-implement it in subclass, the default logic::

            def get_authorization_code_challenge_method(self, authorization_code):
                return authorization_code.code_challenge_method

        :param authorization_code: the instance of authorization_code
        """
        return authorization_code.code_challenge_method
