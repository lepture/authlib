import time
import hmac
import hashlib
from authlib.common.encoding import to_bytes, urlsafe_b64encode
from authlib.specs.rfc7519 import JWTClaims
from authlib.specs.rfc7519 import (
    MissingClaimError,
    InvalidClaimError,
)

_REGISTERED_CLAIMS = [
    'iss', 'sub', 'aud', 'exp', 'nbf', 'iat',
    'auth_time', 'nonce', 'acr', 'amr', 'azp',
    'at_hash',
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
        self.validate_at_hash()

    def validate_auth_time(self):
        """Time when the End-User authentication occurred. Its value is a JSON
        number representing the number of seconds from 1970-01-01T0:0:0Z as
        measured in UTC until the date/time. When a max_age request is made or
        when auth_time is requested as an Essential Claim, then this Claim is
        REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        auth_time = self.get('auth_time')
        if 'max_age' in self.options and not auth_time:
            raise MissingClaimError('auth_time')

        if auth_time and not isinstance(auth_time, int):
            raise InvalidClaimError('auth_time')

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
        """OPTIONAL. Authentication Methods References. JSON array of strings
        that are identifiers for authentication methods used in the
        authentication. For instance, values might indicate that both password
        and OTP authentication methods were used. The definition of particular
        values to be used in the amr Claim is beyond the scope of this
        specification. Parties using this claim will need to agree upon the
        meanings of the values used, which may be context-specific. The amr
        value is an array of case sensitive strings.
        """
        if 'amr' in self:
            if not isinstance(self['amr'], list):
                raise InvalidClaimError('amr')

    def validate_azp(self):
        """OPTIONAL. Authorized party - the party to which the ID Token was
        issued. If present, it MUST contain the OAuth 2.0 Client ID of this
        party. This Claim is only needed when the ID Token has a single
        audience value and that audience is different than the authorized
        party. It MAY be included even when the authorized party is the same
        as the sole audience. The azp value is a case sensitive string
        containing a StringOrURI value.
        """
        azp = self.get('azp')
        if azp:
            aud_option = self.options.get('aud')
            if aud_option and aud_option != azp:
                raise InvalidClaimError('azp')

    def validate_at_hash(self):
        """OPTIONAL. Access Token hash value. Its value is the base64url
        encoding of the left-most half of the hash of the octets of the ASCII
        representation of the access_token value, where the hash algorithm
        used is the hash algorithm used in the alg Header Parameter of the
        ID Token's JOSE Header. For instance, if the alg is RS256, hash the
        access_token value with SHA-256, then take the left-most 128 bits and
        base64url encode them. The at_hash value is a case sensitive string.
        """
        access_token = self.options.get('access_token')
        at_hash = self.get('at_hash')
        if at_hash and access_token:
            if not _verify_hash(at_hash, access_token, self.header['alg']):
                raise InvalidClaimError('at_hash')


class CodeIDToken(IDToken):
    RESPONSE_TYPES = ('code',)
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS


class ImplicitIDToken(IDToken):
    RESPONSE_TYPES = ('id_token', 'id_token token')
    REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS

    def validate_at_hash(self):
        """If the ID Token is issued from the Authorization Endpoint with an
        access_token value, which is the case for the response_type value
        id_token token, this is REQUIRED; it MAY NOT be used when no Access
        Token is issued, which is the case for the response_type value
        id_token.
        """
        access_token = self.options.get('access_token')
        if access_token and 'at_hash' not in self:
            raise MissingClaimError('at_hash')
        super(ImplicitIDToken, self).validate_at_hash()


class HybridIDToken(ImplicitIDToken):
    RESPONSE_TYPES = ('code id_token', 'code token', 'code id_token token')
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS + ['c_hash']

    def validate(self, now=None, leeway=0):
        super(HybridIDToken, self).validate(now=now, leeway=leeway)
        self.validate_c_hash()

    def validate_c_hash(self):
        """Code hash value. Its value is the base64url encoding of the
        left-most half of the hash of the octets of the ASCII representation
        of the code value, where the hash algorithm used is the hash algorithm
        used in the alg Header Parameter of the ID Token's JOSE Header. For
        instance, if the alg is HS512, hash the code value with SHA-512, then
        take the left-most 256 bits and base64url encode them. The c_hash
        value is a case sensitive string.
        If the ID Token is issued from the Authorization Endpoint with a code,
        which is the case for the response_type values code id_token and code
        id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        code = self.options.get('code')
        c_hash = self.get('c_hash')
        if code:
            if not c_hash:
                raise MissingClaimError('c_hash')
            if not _verify_hash(c_hash, code, self.header['alg']):
                raise InvalidClaimError('c_hash')


def get_claim_cls_by_response_type(response_type):
    claims_classes = (CodeIDToken, ImplicitIDToken, HybridIDToken)
    for claims_cls in claims_classes:
        if response_type in claims_cls.RESPONSE_TYPES:
            return claims_cls


def _verify_hash(signature, data, alg):
    hash_type = 'sha{}'.format(alg[2:])
    hash_method = getattr(hashlib, hash_type, None)
    if not hash_method:
        return True
    data_digest = hash_method(to_bytes(data)).digest()
    slice_index = int(len(data_digest) / 2)
    hash_value = urlsafe_b64encode(data_digest[:slice_index])
    return hmac.compare_digest(hash_value, to_bytes(signature))
