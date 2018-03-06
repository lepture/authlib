import time
from .errors import (
    MissingClaimError,
    InvalidClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


class JWTClaims(dict):
    REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']

    def __init__(self, payload, header, options=None):
        super(JWTClaims, self).__init__(payload)
        self.header = header
        self.options = options or {}

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error

    def validate(self, now=None, leeway=0):
        if now is None:
            now = int(time.time())

        self.validate_iss()
        self.validate_sub()
        self.validate_aud()
        self.validate_exp(now, leeway)
        self.validate_nbf(now, leeway)
        self.validate_iat(now, leeway)
        self.validate_jti()

    def validate_iss(self):
        """The "iss" (issuer) claim identifies the principal that issued the
        JWT.  The processing of this claim is generally application specific.
        The "iss" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        """
        iss_option = self.options.get('iss')
        if not iss_option:
            return
        iss = self.get('iss')
        if not iss:
            raise MissingClaimError('iss')

        # if has iss
        if isinstance(iss_option, (list, tuple)):
            if iss not in iss_option:
                raise InvalidClaimError('iss')
        elif iss != iss_option:
            raise InvalidClaimError('iss')

    def validate_sub(self):
        """The "sub" (subject) claim identifies the principal that is the
        subject of the JWT.  The claims in a JWT are normally statements
        about the subject.  The subject value MUST either be scoped to be
        locally unique in the context of the issuer or be globally unique.
        The processing of this claim is generally application specific.  The
        "sub" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        """
        sub_option = self.options.get('sub')
        if sub_option and 'sub' not in self:
            raise MissingClaimError('sub')

    def validate_aud(self):
        """The "aud" (audience) claim identifies the recipients that the JWT is
        intended for.  Each principal intended to process the JWT MUST
        identify itself with a value in the audience claim.  If the principal
        processing the claim does not identify itself with a value in the
        "aud" claim when this claim is present, then the JWT MUST be
        rejected.  In the general case, the "aud" value is an array of case-
        sensitive strings, each containing a StringOrURI value.  In the
        special case when the JWT has one audience, the "aud" value MAY be a
        single case-sensitive string containing a StringOrURI value.  The
        interpretation of audience values is generally application specific.
        Use of this claim is OPTIONAL.
        """
        aud_option = self.options.get('aud')
        if not aud_option:
            return

        if 'aud' not in self:
            raise MissingClaimError('aud')

        if isinstance(self['aud'], list):
            aud_list = self['aud']
        else:
            aud_list = [self['aud']]

        if aud_option not in aud_list:
            raise InvalidClaimError('aud')

    def validate_exp(self, now, leeway):
        """The "exp" (expiration time) claim identifies the expiration time on
        or after which the JWT MUST NOT be accepted for processing.  The
        processing of the "exp" claim requires that the current date/time
        MUST be before the expiration date/time listed in the "exp" claim.
        Implementers MAY provide for some small leeway, usually no more than
        a few minutes, to account for clock skew.  Its value MUST be a number
        containing a NumericDate value.  Use of this claim is OPTIONAL.
        """
        exp_option = self.options.get('exp', {})
        exp = self.get('exp')
        if exp_option and not exp:
            raise MissingClaimError('exp')

        if exp:
            if not isinstance(exp, int):
                raise InvalidClaimError('exp')
            if exp < (now - leeway):
                raise ExpiredTokenError()

    def validate_nbf(self, now, leeway):
        """The "nbf" (not before) claim identifies the time before which the JWT
        MUST NOT be accepted for processing.  The processing of the "nbf"
        claim requires that the current date/time MUST be after or equal to
        the not-before date/time listed in the "nbf" claim.  Implementers MAY
        provide for some small leeway, usually no more than a few minutes, to
        account for clock skew.  Its value MUST be a number containing a
        NumericDate value.  Use of this claim is OPTIONAL.
        """
        nbf_option = self.options.get('nbf', {})
        nbf = self.get('nbf')
        if nbf_option and not nbf:
            raise MissingClaimError('nbf')

        if nbf:
            if not isinstance(nbf, int):
                raise InvalidClaimError('nbf')
            if nbf > (now + leeway):
                raise InvalidTokenError()

    def validate_iat(self, now, leeway):
        """The "iat" (issued at) claim identifies the time at which the JWT was
        issued.  This claim can be used to determine the age of the JWT.  Its
        value MUST be a number containing a NumericDate value.  Use of this
        claim is OPTIONAL.
        """
        iat_option = self.options.get('iat')
        iat = self.get('iat')
        if iat_option and not iat:
            raise MissingClaimError('iat')

        if iat and not isinstance(iat, int):
            raise InvalidClaimError('iat')

    def validate_jti(self):
        """The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        The identifier value MUST be assigned in a manner that ensures that
        there is a negligible probability that the same value will be
        accidentally assigned to a different data object; if the application
        uses multiple issuers, collisions MUST be prevented among values
        produced by different issuers as well.  The "jti" claim can be used
        to prevent the JWT from being replayed.  The "jti" value is a case-
        sensitive string.  Use of this claim is OPTIONAL.
        """
        jti_option = self.options.get('jti')
        if jti_option:
            if 'jti' not in self:
                raise MissingClaimError('jti')

            if callable(jti_option):
                # validate jti value
                if not jti_option(self['jti']):
                    raise InvalidClaimError('jti')
