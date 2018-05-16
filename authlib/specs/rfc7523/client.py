import logging
from authlib.common.security import generate_token
from ..rfc6749 import InvalidClientError
from ..rfc7519 import jwt, JWTError
from .assertion import sign_jwt_bearer_assertion

ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
log = logging.getLogger(__name__)


class JWTBearerClientAssertion(object):
    """Implementation of Using JWTs for Client Authentication, which is
    defined by RFC7523.
    """
    CLIENT_ASSERTION_TYPE = ASSERTION_TYPE
    CLIENT_AUTH_METHOD = 'client_secret_jwt'

    def __init__(self, token_url):
        self.token_url = token_url

    def __call__(self, query_client, request):
        data = dict(request.body_params)
        assertion_type = data.get('client_assertion_type')
        assertion = data.get('client_assertion')
        if assertion_type == ASSERTION_TYPE and assertion:
            resolve_key = self.create_resolve_key_func(query_client, request)
            claims = self.process_assertion_claims(assertion, resolve_key)
            return self.authenticate_client(query_client, claims, request)
        log.debug('Authenticate via "{}" failed'.format(self.CLIENT_AUTH_METHOD))

    def create_claims_options(self):
        """Create a claims_options for verify JWT payload claims. Developers
        MAY overwrite this method to create a more strict options."""
        # https://tools.ietf.org/html/rfc7523#section-3
        # The Audience SHOULD be the URL of the Authorization Server's Token Endpoint
        return {
            'iss': {'essential': True},
            'sub': {'essential': True},
            'aud': {'essential': True, 'value': self.token_url},
            'exp': {'essential': True},
        }

    def process_assertion_claims(self, assertion, resolve_key):
        """Extract JWT payload claims from request "assertion", per
        `Section 3.1`_.

        :param assertion: assertion string value in the request
        :param resolve_key: function to resolve the sign key
        :return: JWTClaims
        :raise: InvalidClientError

        .. _`Section 3.1`: https://tools.ietf.org/html/rfc7523#section-3.1
        """
        claims = jwt.decode(
            assertion, resolve_key,
            claims_options=self.create_claims_options())
        try:
            claims.validate()
        except JWTError as e:
            log.debug('Assertion Error: {!r}'.format(e))
            raise InvalidClientError()
        return claims

    def authenticate_client(self, query_client, claims, request):
        # https://tools.ietf.org/html/rfc7523#section-3
        # For client authentication, the subject MUST be the
        # "client_id" of the OAuth client
        if request.client:
            client = request.client
        else:
            client = query_client(claims['sub'])
        if client.check_token_endpoint_auth_method(self.CLIENT_AUTH_METHOD):
            return client
        raise InvalidClientError()

    def create_resolve_key_func(self, query_client, request):
        raise NotImplementedError()


class ClientSecretJWT(JWTBearerClientAssertion):
    """A more clearly definition of Using JWTs for Client Authentication. This
    implementation is defined by OpenID Connect, which is called
    ``client_secret_jwt``.
    """
    # http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

    #: name of the authentication method
    CLIENT_AUTH_METHOD = 'client_secret_jwt'
    #: default ``alg`` to sign the signature
    JWT_SIGN_ALG = 'HS256'

    @classmethod
    def sign(cls, key, client_id, token_url, claims=None, **kwargs):
        # REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
        issuer = client_id
        # REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
        subject = client_id
        # The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
        audience = token_url

        # jti is required
        if claims is None:
            claims = {}
        if 'jti' not in claims:
            claims['jti'] = generate_token(36)

        alg = kwargs.pop('alg', cls.JWT_SIGN_ALG)
        return sign_jwt_bearer_assertion(
            key, issuer, audience, subject,
            claims, alg=alg, **kwargs)

    def validate_jti(self, claims, jti):
        """Validate if the given ``jti`` value is used before. Developers
        MUST implement this method::

            def validate_jti(self, claims, jti):
                key = 'jti:{}-{}'.format(claims['sub'], jti)
                if redis.get(key):
                    return False
                redis.set(key, 1, ex=3600)
                return True
        """
        raise NotImplementedError()

    def create_claims_options(self):
        options = super(ClientSecretJWT, self).create_claims_options()
        # REQUIRED. JWT ID. A unique identifier for the token, which can be
        # used to prevent reuse of the token. These tokens MUST only be used
        # once, unless conditions for reuse were negotiated between the
        # parties; any such negotiation is beyond the scope of this specification.
        options['jti'] = {'essential': True, 'validate': self.validate_jti}

        # REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
        options['iss'] = {'essential': True, 'validate': _validate_iss}
        return options

    def create_resolve_key_func(self, query_client, request):
        def resolve_client_secret(headers, payload):
            client_id = payload['sub']
            client = query_client(client_id)
            request.client = client
            return client.get_client_secret()
        return resolve_client_secret


class PrivateKeyJWT(ClientSecretJWT):
    """A more clearly definition of Using JWTs for Client Authentication. This
    implementation is defined by OpenID Connect, which is called
    ``private_key_jwt``.
    """
    #: name of the authentication method
    CLIENT_AUTH_METHOD = 'private_key_jwt'
    #: default ``alg`` to sign the signature
    JWT_SIGN_ALG = 'RS256'

    def resolve_client_public_key(self, client, headers):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            def resolve_client_public_key(self, client, headers):
                return client.public_key
        """
        raise NotImplementedError()

    def create_resolve_key_func(self, query_client, request):
        def resolve_key(headers, payload):
            client_id = payload['sub']
            client = query_client(client_id)
            return self.resolve_client_public_key(client, headers)
        return resolve_key


def _validate_iss(claims, iss):
    return claims['sub'] == iss
