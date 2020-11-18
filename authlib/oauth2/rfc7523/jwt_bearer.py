import logging
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from ..rfc6749 import BaseGrant, TokenEndpointMixin
from ..rfc6749 import (
    UnauthorizedClientError,
    InvalidRequestError,
    InvalidGrantError
)
from .assertion import sign_jwt_bearer_assertion

log = logging.getLogger(__name__)
JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class JWTBearerGrant(BaseGrant, TokenEndpointMixin):
    GRANT_TYPE = JWT_BEARER_GRANT_TYPE

    @staticmethod
    def sign(key, issuer, audience, subject=None,
             issued_at=None, expires_at=None, claims=None, **kwargs):
        return sign_jwt_bearer_assertion(
            key, issuer, audience, subject, issued_at,
            expires_at, claims, **kwargs)

    def create_claims_options(self):
        """Create a claims_options for verify JWT payload claims. Developers
        MAY overwrite this method to create a more strict options.
        """
        # https://tools.ietf.org/html/rfc7523#section-3
        return {
            'iss': {'essential': True},
            'sub': {'essential': True},
            'aud': {'essential': True},
            'exp': {'essential': True},
        }

    def process_assertion_claims(self, assertion):
        """Extract JWT payload claims from request "assertion", per
        `Section 3.1`_.

        :param assertion: assertion string value in the request
        :return: JWTClaims
        :raise: InvalidGrantError

        .. _`Section 3.1`: https://tools.ietf.org/html/rfc7523#section-3.1
        """
        claims = jwt.decode(
            assertion, self.resolve_public_key,
            claims_options=self.create_claims_options())
        try:
            claims.validate()
        except JoseError as e:
            log.debug('Assertion Error: %r', e)
            raise InvalidGrantError(description=e.description)
        return claims

    def validate_token_request(self):
        """The client makes a request to the token endpoint by sending the
        following parameters using the "application/x-www-form-urlencoded"
        format per `Section 2.1`_:

        grant_type
             REQUIRED.  Value MUST be set to
             "urn:ietf:params:oauth:grant-type:jwt-bearer".

        assertion
             REQUIRED.  Value MUST contain a single JWT.

        scope
            OPTIONAL.

        The following example demonstrates an access token request with a JWT
        as an authorization grant:

        .. code-block:: http

            POST /token.oauth2 HTTP/1.1
            Host: as.example.com
            Content-Type: application/x-www-form-urlencoded

            grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
            &assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.
            eyJpc3Mi[...omitted for brevity...].
            J9l-ZhwP[...omitted for brevity...]

        .. _`Section 2.1`: https://tools.ietf.org/html/rfc7523#section-2.1
        """
        assertion = self.request.form.get('assertion')
        if not assertion:
            raise InvalidRequestError('Missing "assertion" in request')

        claims = self.process_assertion_claims(assertion)
        client = self.authenticate_client(claims)
        log.debug('Validate token request of %s', client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        self.request.client = client
        self.validate_requested_scope()
        self.request.user = self.authenticate_user(client, claims)

    def create_token_response(self):
        """If valid and authorized, the authorization server issues an access
        token.
        """
        token = self.generate_token(
            scope=self.request.scope,
            include_refresh_token=False,
        )
        log.debug('Issue token %r to %r', token, self.request.client)
        self.save_token(token)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def authenticate_user(self, client, claims):
        """Authenticate user with the given assertion claims. Developers MUST
        implement it in subclass, e.g.::

            def authenticate_user(self, client, claims):
                user = User.get_by_sub(claims['sub'])
                if is_authorized_to_client(user, client):
                    return user

        :param client: OAuth Client instance
        :param claims: assertion payload claims
        :return: User instance
        """
        raise NotImplementedError()

    def authenticate_client(self, claims):
        """Authenticate client with the given assertion claims. Developers MUST
        implement it in subclass, e.g.::

            def authenticate_client(self, claims):
                return Client.get_by_iss(claims['iss'])

        :param claims: assertion payload claims
        :return: Client instance
        """
        raise NotImplementedError()

    def resolve_public_key(self, headers, payload):
        """Find public key to verify assertion signature. Developers MUST
        implement it in subclass, e.g.::

            def resolve_public_key(self, headers, payload):
                jwk_set = get_jwk_set_by_iss(payload['iss'])
                return filter_jwk_set(jwk_set, headers['kid'])

        :param headers: JWT headers dict
        :param payload: JWT payload dict
        :return: A public key
        """
        raise NotImplementedError()
