from authlib.deprecate import deprecate
from ..rfc6749.grants import AuthorizationCodeGrant as _CodeGrant
from .challenge import CodeChallenge


class AuthorizationCodeGrant(_CodeGrant):  # pragma: no cover
    def __init__(self, *args, **kwargs):
        super(AuthorizationCodeGrant, self).__init__(*args, **kwargs)
        deprecate('Use CodeChallenge as an extension instead.', '0.12', 'fAmW1', 'CC')
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
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        return authorization_code.code_challenge_method
