import logging
from authlib.oauth2.rfc6749 import (
    OAuth2Error,
    InvalidScopeError,
    UnauthorizedClientError,
    InvalidClientError,
)
from .implicit import OpenIDImplicitGrant
from .util import (
    is_openid_scope,
    validate_nonce,
)

log = logging.getLogger(__name__)


class OpenIDHybridGrant(OpenIDImplicitGrant):
    RESPONSE_TYPES = {'code id_token', 'code token', 'code id_token token'}
    GRANT_TYPE = 'code'
    DEFAULT_RESPONSE_MODE = 'fragment'

    def create_authorization_code(self, client, grant_user, request):
        """Save authorization_code for later use. Developers should implement
        it in subclass. Here is an example::

            from authlib.common.security import generate_token

            def create_authorization_code(self, client, request):
                code = generate_token(48)
                item = AuthorizationCode(
                    code=code,
                    client_id=client.client_id,
                    redirect_uri=request.redirect_uri,
                    scope=request.scope,
                    nonce=request.data.get('nonce'),
                    user_id=grant_user.get_user_id(),
                )
                item.save()
                return code

        :param client: the client that requesting the token.
        :param grant_user: the resource owner that grant the permission.
        :param request: OAuth2Request instance.
        :return: code string
        """
        raise NotImplementedError()

    def generate_user_info(self, user, scopes):
        raise NotImplementedError()

    def validate_authorization_request(self):
        if not is_openid_scope(self.request.scope):
            raise InvalidScopeError(
                'Missing "openid" scope',
                redirect_uri=self.request.redirect_uri,
                redirect_fragment=True,
            )

        client_id = self.request.client_id
        log.debug('Validate authorization request of %r', client_id)

        if client_id is None:
            raise InvalidClientError(
                state=self.request.state,
                redirect_uri=self.request.redirect_uri,
            )

        client = self.server.query_client(client_id)
        if not client:
            raise InvalidClientError(
                state=self.request.state,
                redirect_uri=self.request.redirect_uri,
            )

        redirect_uri = self.validate_authorization_redirect_uri(self.request, client)
        response_type = self.request.response_type
        if not client.check_response_type(response_type):
            raise UnauthorizedClientError(
                'The client is not authorized to use '
                '"response_type={}"'.format(response_type),
                state=self.request.state,
                redirect_uri=redirect_uri,
            )

        try:
            self.validate_requested_scope(client)
            self.request.client = client
            validate_nonce(self.request, self.exists_nonce, required=True)
            self.execute_hook('after_validate_authorization_request')
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            error.redirect_fragment = True
            raise error
        return redirect_uri

    def create_granted_params(self, grant_user):
        self.request.user = grant_user
        client = self.request.client

        code = self.create_authorization_code(
            client, grant_user, self.request)
        params = [('code', code)]

        token = self.generate_token(
            client, 'implicit',
            user=grant_user,
            scope=self.request.scope,
            include_refresh_token=False
        )

        response_types = self.request.response_type.split()
        if 'token' in response_types:
            log.debug('Grant token %r to %r', token, client)
            self.server.save_token(token, self.request)
            if 'id_token' in response_types:
                token = self.process_implicit_token(token, code)
        else:
            # response_type is "code id_token"
            token = {
                'expires_in': token['expires_in'],
                'scope': token['scope']
            }
            token = self.process_implicit_token(token, code)

        params.extend([(k, token[k]) for k in token])
        return params

