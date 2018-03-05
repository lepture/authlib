import time
from authlib.specs.rfc7519 import JWTClaims
from authlib.specs.rfc7519 import (
    MissingClaimError,
    InvalidClaimError,
)

BASE_AVAILABLE_CLAIMS = [
    'iss', 'sub', 'aud', 'exp', 'nbf', 'iat',
    'auth_time', 'nonce', 'acr', 'amr', 'azp'
]


class IDToken(JWTClaims):
    REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat']

    def __init__(self, payload, header, options=None):
        if options is None:
            options = {}
        options.update({
            'iat': True,
        })
        super(IDToken, self).__init__(payload, header, options)

    def validate(self, now=None, leeway=0):
        for k in self.REQUIRED_CLAIMS:
            if k not in self:
                raise MissingClaimError(k)

        if now is None:
            now = int(time.time())

        self.validate_iss()
        self.validate_sub()
        self.validate_aud()
        self.validate_exp(now, leeway)
        self.validate_nbf(now, leeway)
        self.validate_iat(now, leeway)
        self.validate_auth_time()
        self.validate_nonce()
        self.validate_acr()
        self.validate_amr()
        self.validate_azp()

    def validate_auth_time(self):
        pass

    def validate_nonce(self):
        nonce_option = self.options.get('nonce')
        if nonce_option:
            if 'nonce' not in self:
                raise MissingClaimError('nonce')
            if nonce_option != self['nonce']:
                raise InvalidClaimError('nonce')

    def validate_acr(self):
        pass

    def validate_amr(self):
        pass

    def validate_azp(self):
        pass


class CodeIDToken(IDToken):
    RESPONSE_TYPES = ('code',)
    REGISTERED_CLAIMS = BASE_AVAILABLE_CLAIMS + ['at_hash']

    def validate(self, now=None, leeway=0):
        super(CodeIDToken, self).validate(now=now, leeway=leeway)
        self.validate_at_hash()

    def validate_at_hash(self):
        pass


class ImplicitIDToken(IDToken):
    RESPONSE_TYPES = ('id_token', 'id_token token')
    REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']
    REGISTERED_CLAIMS = BASE_AVAILABLE_CLAIMS + ['at_hash']

    def validate(self, now=None, leeway=0):
        super(ImplicitIDToken, self).validate(now=now, leeway=leeway)
        self.validate_at_hash()

    def validate_at_hash(self):
        pass


class HybridIDToken(ImplicitIDToken):
    RESPONSE_TYPES = ('code id_token', 'code token', 'code id_token token')
    REGISTERED_CLAIMS = BASE_AVAILABLE_CLAIMS + ['at_hash', 'c_hash']

    def validate(self, now=None, leeway=0):
        super(HybridIDToken, self).validate(now=now, leeway=leeway)
        self.validate_at_hash()
        self.validate_c_hash()

    def validate_at_hash(self):
        pass

    def validate_c_hash(self):
        pass


def get_claim_cls_by_response_type(response_type):
    claims_classes = (CodeIDToken, ImplicitIDToken, HybridIDToken)
    for claims_cls in claims_classes:
        if response_type in claims_cls.RESPONSE_TYPES:
            return claims_cls
