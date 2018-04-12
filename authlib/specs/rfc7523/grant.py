import logging
from ..rfc6749.grants import BaseGrant
from ..rfc6749 import UnauthorizedClientError, InvalidRequestError
from ..rfc7519 import JWT
from .consts import JWT_BEARER_GRANT_TYPE

log = logging.getLogger(__name__)


class JWTBearerGrant(BaseGrant):
    SPECIFICATION = 'rfc7523'
    GRANT_TYPE = JWT_BEARER_GRANT_TYPE

    def validate_assertion(self):
        assertion = self.request.data.get('assertion')
        if not assertion:
            raise InvalidRequestError('Missing "assertion" in request')

        # TODO: make algorithms configurable
        jwt = JWT()
        # TODO: claims options
        claims = jwt.decode(assertion, self.resolve_public_key)
        claims.validate()
        return claims

    def validate_token_request(self):
        claims = self.validate_assertion()
        client = self.authenticate_client(claims)
        log.debug('Validate token request of {!r}'.format(client))

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        self.validate_requested_scope(client)
        self.request.user = self.authenticate_user(claims)
        self.request.client = client

    def create_token_response(self):
        client = self.request.client
        token = self.generate_token(
            client, self.GRANT_TYPE,
            scope=self.request.scope,
            include_refresh_token=False,
        )
        log.debug('Issue token {!r} to {!r}'.format(token, client))
        self.server.save_token(token, self.request)
        token = self.process_token(token, self.request)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    def authenticate_user(self, claims):
        raise NotImplementedError()

    def authenticate_client(self, claims):
        raise NotImplementedError()

    def resolve_public_key(self, headers, payload):
        raise NotImplementedError()
