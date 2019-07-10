import logging
from authlib.deprecate import deprecate
from authlib.oauth2.rfc6749 import (
    OAuth2Error,
    InvalidScopeError,
    AccessDeniedError,
)
from authlib.oauth2.rfc6749.grants import ImplicitGrant
from authlib.oauth2.rfc6749.util import scope_to_list
from .util import (
    is_openid_scope,
    validate_nonce,
    validate_request_prompt,
    create_response_mode_response,
    generate_id_token,
    _generate_user_info,
)

log = logging.getLogger(__name__)


class OpenIDImplicitGrant(ImplicitGrant):
    RESPONSE_TYPES = {'id_token token', 'id_token'}
    DEFAULT_RESPONSE_MODE = 'fragment'

    def exists_nonce(self, nonce, request):
        """Check if the given nonce is existing in your database. Developers
        should implement this method in subclass, e.g.::

            def exists_nonce(self, nonce, request):
                exists = AuthorizationCode.query.filter_by(
                    client_id=req.client_id, nonce=nonce
                ).first()
                return bool(exists)

        :param nonce: A string of "nonce" parameter in request
        :param request: OAuth2Request instance
        :return: Boolean
        """
        raise NotImplementedError()

    def get_jwt_config(self):  # pragma: no cover
        # TODO: developers MUST re-implement this method
        deprecate('Missing "OpenIDImplicitGrant.get_jwt_config"', '1.0', 'TODO', 'oi')
        config = self.server.config
        key = config['jwt_key']
        alg = config['jwt_alg']
        iss = config['jwt_iss']
        exp = config['jwt_exp']
        return dict(key=key, alg=alg, iss=iss, exp=exp)

    def generate_user_info(self, user, scopes):  # pragma: no cover
        # TODO: developers MUST re-implement this method
        deprecate('Missing "OpenIDImplicitGrant.generate_user_info"', '1.0', 'TODO', 'oi')
        return _generate_user_info(user, scopes)

    def validate_authorization_request(self):
        if not is_openid_scope(self.request.scope):
            raise InvalidScopeError(
                'Missing "openid" scope',
                redirect_uri=self.request.redirect_uri,
                redirect_fragment=True,
            )
        redirect_uri = super(
            OpenIDImplicitGrant, self).validate_authorization_request()
        try:
            validate_nonce(self.request, self.exists_nonce, required=True)
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            error.redirect_fragment = True
            raise error
        return redirect_uri

    def validate_consent_request(self):
        redirect_uri = self.validate_authorization_request()
        validate_request_prompt(self, redirect_uri, redirect_fragment=True)

    def create_authorization_response(self, redirect_uri, grant_user):
        state = self.request.state
        if grant_user:
            params = self.create_granted_params(grant_user)
            if state:
                params.append(('state', state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

        # http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
        response_mode = self.request.data.get('response_mode', self.DEFAULT_RESPONSE_MODE)
        return create_response_mode_response(
            redirect_uri=redirect_uri,
            params=params,
            response_mode=response_mode,
        )

    def create_granted_params(self, grant_user):
        self.request.user = grant_user
        client = self.request.client
        token = self.generate_token(
            client, self.GRANT_TYPE,
            user=grant_user,
            scope=self.request.scope,
            include_refresh_token=False
        )
        if self.request.response_type == 'id_token':
            token = {
                'expires_in': token['expires_in'],
                'scope': token['scope'],
            }
            token = self.process_implicit_token(token)
        else:
            log.debug('Grant token %r to %r', token, client)
            self.server.save_token(token, self.request)
            token = self.process_implicit_token(token)
        params = [(k, token[k]) for k in token]
        return params

    def process_implicit_token(self, token, code=None):
        config = self.get_jwt_config()
        config['nonce'] = self.request.data.get('nonce')
        if code is not None:
            config['code'] = code

        scopes = scope_to_list(token['scope'])
        user_info = self.generate_user_info(self.request.user, scopes)

        id_token = generate_id_token(token, self.request, user_info, **config)
        token['id_token'] = id_token
        return token
