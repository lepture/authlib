import json
from .jws import jws


class IDToken(object):
    """ID Token model, per `Section 2`_ and other sections of the OpenID
    Connect Core spec.

    :param token: Parsed token dict from id_token string.

    .. _`Section 2`: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    """
    def __init__(self, token):
        self.token = token

    @property
    def iss(self):
        """REQUIRED. Issuer Identifier for the Issuer of the response. The iss
        value is a case sensitive URL using the https scheme that contains
        scheme, host, and optionally, port number and path components and no
        query or fragment components.
        """
        return self.token['iss']

    @property
    def sub(self):
        """REQUIRED. Subject Identifier. A locally unique and never reassigned
        identifier within the Issuer for the End-User, which is intended to be
        consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutr.
        It MUST NOT exceed 255 ASCII characters in length. The sub value is a
        case sensitive string.
        """
        return self.token['sub']

    @property
    def aud(self):
        """REQUIRED. Audience(s) that this ID Token is intended for. It MUST
        contain the OAuth 2.0 client_id of the Relying Party as an audience
        value. It MAY also contain identifiers for other audiences. In the
        general case, the aud value is an array of case sensitive strings. In
        the common special case when there is one audience, the aud value MAY
        be a single case sensitive string.
        """
        return self.token['aud']

    @property
    def exp(self):
        """REQUIRED. Expiration time on or after which the ID Token MUST NOT
        be accepted for processing. The processing of this parameter requires
        that the current date/time MUST be before the expiration date/time
        listed in the value. Implementers MAY provide for some small leeway,
        usually no more than a few minutes, to account for clock skew. Its
        value is a JSON number representing the number of seconds from
        1970-01-01T0:0:0Z as measured in UTC until the date/time. See
        `RFC 3339`_ for details regarding date/times in general and UTC in
        particular.

        .. _`RFC 3339`: http://tools.ietf.org/html/rfc3339
        """
        return self.token['exp']

    @property
    def iat(self):
        """REQUIRED. Time at which the JWT was issued. Its value is a JSON
        number representing the number of seconds from 1970-01-01T0:0:0Z as
        measured in UTC until the date/time.
        """
        return self.token['iat']

    @property
    def auth_time(self):
        """Time when the End-User authentication occurred. Its value is a JSON
        number representing the number of seconds from 1970-01-01T0:0:0Z as
        measured in UTC until the date/time. When a max_age request is made or
        when auth_time is requested as an Essential Claim, then this Claim is
        REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        return self.token.get('auth_time')

    @property
    def nonce(self):
        """String value used to associate a Client session with an ID Token,
        and to mitigate replay attacks. The value is passed through unmodified
        from the Authentication Request to the ID Token. If present in the ID
        Token, Clients MUST verify that the nonce Claim Value is equal to the
        value of the nonce parameter sent in the Authentication Request. If
        present in the Authentication Request, Authorization Servers MUST
        include a nonce Claim in the ID Token with the Claim Value being the
        nonce value sent in the Authentication Request. Authorization Servers
        SHOULD perform no other processing on nonce values used. The nonce
        value is a case sensitive string.
        """
        return self.token.get('nonce')

    @property
    def acr(self):
        """OPTIONAL. Authentication Context Class Reference. String specifying
        an Authentication Context Class Reference value that identifies the
        Authentication Context Class that the authentication performed
        satisfied. The value "0" indicates the End-User authentication did not
        meet the requirements of `ISO/IEC 29115`_ level 1. Authentication
        using a long-lived browser cookie, for instance, is one example where
        the use of "level 0" is appropriate. Authentications with level 0
        SHOULD NOT be used to authorize access to any resource of any monetary
        value. An absolute URI or an `RFC 6711`_ registered name SHOULD be
        used as the acr value; registered names MUST NOT be used with a
        different meaning than that which is registered. Parties using this
        claim will need to agree upon the meanings of the values used, which
        may be context-specific. The acr value is a case sensitive string.

        .. _`ISO/IEC 29115`: https://www.iso.org/standard/45138.html
        .. _`RFC 6711`: http://tools.ietf.org/html/rfc6711
        """
        return self.token.get('acr')

    @property
    def amr(self):
        """OPTIONAL. Authentication Methods References. JSON array of strings
        that are identifiers for authentication methods used in the
        authentication. For instance, values might indicate that both password
        and OTP authentication methods were used. Parties using this claim
        will need to agree upon the meanings of the values used, which may be
        context-specific. The amr value is an array of case sensitive strings.
        """
        return self.token.get('amr')

    @property
    def azp(self):
        """OPTIONAL. Authorized party - the party to which the ID Token was
        issued. If present, it MUST contain the OAuth 2.0 Client ID of this
        party. This Claim is only needed when the ID Token has a single
        audience value and that audience is different than the authorized
        party. It MAY be included even when the authorized party is the same
        as the sole audience. The azp value is a case sensitive string
        containing a StringOrURI value.
        """
        return self.token.get('azp')

    def validate_iss(self, issuer):
        if 'iss' not in self.token:
            raise IDTokenError('iss is required')
        if isinstance(issuer, (list, tuple)):
            if self.iss not in issuer:
                raise IDTokenError('iss is invalid')
        elif issuer is not None and self.iss != issuer:
            raise IDTokenError('iss is invalid')

    def validate_sub(self):
        if 'sub' not in self.token:
            raise IDTokenError('sub is required')
        if len(self.sub) > 255:
            raise IDTokenError('sub exceed 255 in length')

    def validate_aud(self, client_id):
        # aud is required
        if 'aud' not in self.token:
            raise IDTokenError('aud is required')
        if isinstance(self.aud, (list, tuple)):
            aud_list = self.aud
        else:
            aud_list = (self.aud,)
        if client_id and client_id not in aud_list:
            raise IDTokenError('aud is not for this client')

    def validate_exp(self, now):
        if 'exp' not in self.token:
            raise IDTokenError('exp is required')
        if now and self.exp > now:
            raise IDTokenError('exp is expired')

    def validate_iat(self):
        if 'iat' not in self.token:
            raise IDTokenError('iat is required')

    def validate_auth_time(self, max_age):
        if max_age and 'auth_time' not in self.token:
            raise IDTokenError('auth_time is required')

    def validate_nonce(self, nonce):
        if nonce and nonce != self.nonce:
            raise IDTokenError('nonce is invalid')

    def validate_azp(self, client_id):
        if self.azp or len(self.aud) > 1:
            if self.azp != client_id:
                raise IDTokenError('azp is not for this client')

    def validate(self, issuers=None, client_id=None, nonce=None, max_age=None,
                 now=None, **kwargs):
        """ID Token Validation, per `Section 3.1.3.7`_.

        .. _`Section 3.1.3.7`:
            http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        self.validate_iss(issuers)
        self.validate_sub()
        self.validate_aud(client_id)
        self.validate_exp(now)
        self.validate_iat()
        self.validate_auth_time(max_age)
        self.validate_nonce(nonce)
        self.validate_azp(client_id)


class CodeIDToken(IDToken):
    """Implement IDToken when using the Code Flow. Per `Sectin 3.1.3.6`_.

    .. _`Sectin 3.1.3.6`: http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
    """
    RESPONSE_TYPES = ('code',)

    @property
    def at_hash(self):
        """OPTIONAL. Access Token hash value. Its value is the base64url
        encoding of the left-most half of the hash of the octets of the ASCII
        representation of the access_token value, where the hash algorithm
        used is the hash algorithm used in the alg Header Parameter of the ID
        Token's JOSE Header. For instance, if the alg is RS256, hash the
        access_token value with SHA-256, then take the left-most 128 bits and
        base64url encode them. The at_hash value is a case sensitive string.
        """
        return self.token.get('at_hash')

    def validate_at_hash(self, alg):
        pass


class ImplicitIDToken(IDToken):
    """Implement IDToken when using the Implicit Flow. Per `Section 3.2.2.10`_

    .. _`Section 3.2.2.10`: http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
    """
    RESPONSE_TYPES = ('id_token', 'id_token token')

    @property
    def nonce(self):
        """Use of the nonce Claim is REQUIRED for this flow."""
        return self.token['nonce']

    @property
    def at_hash(self):
        """Access Token hash value. Its value is the base64url encoding of the
        left-most half of the hash of the octets of the ASCII representation
        of the access_token value, where the hash algorithm used is the hash
        algorithm used in the alg Header Parameter of the ID Token's JOSE
        Header. For instance, if the alg is RS256, hash the access_token value
        with SHA-256, then take the left-most 128 bits and base64url encode
        them. The at_hash value is a case sensitive string.
        """
        return self.token.get('at_hash')

    def validate_nonce(self, nonce):
        if 'nonce' not in self.token:
            raise IDTokenError('nonce is required')
        if nonce != self.nonce:
            raise IDTokenError('nonce is invalid')

    def validate_at_hash(self, header):
        """If the ID Token is issued from the Authorization Endpoint with an
        access_token value, which is the case for the response_type value
        id_token token, this is REQUIRED; it MAY NOT be used when no Access
        Token is issued, which is the case for the response_type value
        id_token.
        """


class HybridIDToken(ImplicitIDToken):
    """Implement IDToken when using the Hybrid Flow. Per `Section 3.3.2.11`_.

    .. _`Section 3.3.2.11`: http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
    """
    RESPONSE_TYPES = ('code id_token', 'code token', 'code id_token token')

    @property
    def c_hash(self):
        """Code hash value. Its value is the base64url encoding of the
        left-most half of the hash of the octets of the ASCII representation
        of the code value, where the hash algorithm used is the hash algorithm
        used in the alg Header Parameter of the ID Token's JOSE Header. For
        instance, if the alg is HS512, hash the code value with SHA-512, then
        take the left-most 256 bits and base64url encode them. The c_hash
        value is a case sensitive string. If the ID Token is issued from the
        Authorization Endpoint with a code, which is the case for the
        response_type values code id_token and code id_token token,
        this is REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        return self.token.get('c_hash')

    def validate_at_hash(self, header):
        """If the ID Token is issued from the Authorization Endpoint with an
        access_token value, which is the case for the response_type value code
        id_token token, this is REQUIRED; otherwise, its inclusion is
        OPTIONAL.
        """


class IDTokenError(ValueError):
    def __init__(self, message):
        self.message = message


def parse_id_token(id_token, key):
    """Parse an id_token text string into token dict.

    :param id_token: A JWS text that represent current id_token.
    :param key: A PEM key to parse the given id_token. This value can be:
                * a string text of PEM key
                * a dict/string of JWK
                * a set/list/tuple of JWK
    :return: (token, header)
    """
    payload, header, valid = jws.parse(id_token, key)
    if not valid:
        raise IDTokenError('Invalid signature')
    token = json.loads(payload.decode('utf-8'))
    return token, header


def validate_id_token(token, response_type='code', header=None, issuers=None,
                      client_id=None, nonce=None, max_age=None, now=None):
    """Validate the parsed id_token.

    :param token: The parsed id_token dict.
    :param response_type: Current OAuth response_type.
    :param header: The header parsed from id_token JWS.
    :param issuers: A string or list to validate for iss in id_token.
    :param client_id: OAuth client_id string to validate aud in id_token.
    :param nonce: OAuth nonce string to validate nonce in id_token.
    :param max_age: A max_age parameter in OAuth authorization.
    :param now: Current timestamp to validate exp in id_token.
    :return: IDToken
    """
    if response_type == 'code':
        cls = CodeIDToken
    elif response_type in ImplicitIDToken.RESPONSE_TYPES:
        cls = ImplicitIDToken
    elif response_type in HybridIDToken.RESPONSE_TYPES:
        cls = HybridIDToken
    else:
        raise ValueError('Invalid response_type')

    obj = cls(token)
    obj.validate(
        issuers=issuers, client_id=client_id,
        nonce=nonce, max_age=max_age,
        header=header,
    )
    return obj


def verify_id_token(response, key, response_type='code', issuers=None,
                    client_id=None, nonce=None, max_age=None):
    """Parse and validate id_token in response."""
    if 'id_token' not in response:
        raise ValueError('Invalid OpenID response')

    token, header = parse_id_token(response['id_token'], key)
    return validate_id_token(
        token, response_type, header, issuers, client_id, nonce, max_age)
