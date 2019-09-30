"""
    authlib.oidc.core.grants.code
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implementation of Authentication using the Authorization Code Flow
    per `Section 3.1`_.

    .. _`Section 3.1`: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging
from authlib.deprecate import deprecate
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.util import scope_to_list
from .util import (
    is_openid_scope,
    validate_nonce,
    validate_request_prompt,
    generate_id_token,
    _generate_user_info,
)

log = logging.getLogger(__name__)


class OpenIDCode(object):
    """An extension from OpenID Connect for "grant_type=code" request.
    """
    def __init__(self, require_nonce=False, **kwargs):
        self.require_nonce = require_nonce
        if 'required_nonce' in kwargs:
            deprecate('Use "require_nonce" instead', '1.0')
            if kwargs['required_nonce']:
                self.require_nonce = True

        self.key = kwargs.get('key')
        self.alg = kwargs.get('alg')
        self.iss = kwargs.get('iss')
        self.exp = kwargs.get('exp')
        self._exists_nonce = kwargs.get('exists_nonce')

    def exists_nonce(self, nonce, request):  # pragma: no cover
        """Check if the given nonce is existing in your database. Developers
        MUST implement this method in subclass, e.g.::

            def exists_nonce(self, nonce, request):
                exists = AuthorizationCode.query.filter_by(
                    client_id=request.client_id, nonce=nonce
                ).first()
                return bool(exists)

        :param nonce: A string of "nonce" parameter in request
        :param request: OAuth2Request instance
        :return: Boolean
        """
        deprecate('Missing "OpenIDCode.exists_nonce"', '1.0', 'fjPsV', 'oi')
        return self._exists_nonce(nonce, request)

    def get_jwt_config(self, grant):  # pragma: no cover
        """Get the JWT configuration for OpenIDCode extension. The JWT
        configuration will be used to generate ``id_token``. Developers
        MUST implement this method in subclass, e.g.::

            def get_jwt_config(self, grant):
                return {
                    'key': read_private_key_file(key_path),
                    'alg': 'RS512',
                    'iss': 'issuer-identity',
                    'exp': 3600
                }

        :param grant: AuthorizationCodeGrant instance
        :return: dict
        """
        deprecate('Missing "OpenIDCode.get_jwt_config"', '1.0', 'fjPsV', 'oi')
        return dict(key=self.key, alg=self.alg, iss=self.iss, exp=self.exp)

    def generate_user_info(self, user, scope):  # pragma: no cover
        """Provide user information for the given scope. Developers
        MUST implement this method in subclass, e.g.::

            from authlib.oidc.core import UserInfo

            def generate_user_info(self, user, scope):
                user_info = UserInfo(sub=user.id, name=user.name)
                if 'email' in scope:
                    user_info['email'] = user.email
                return user_info

        :param user: user instance
        :param scope: scope of the token
        :return: ``authlib.oidc.core.UserInfo`` instance
        """
        deprecate('Missing "OpenIDCode.generate_user_info"', '1.0', 'fjPsV', 'oi')
        scopes = scope_to_list(scope)
        return _generate_user_info(user, scopes)

    def get_audiences(self, request):
        """Parse `aud` value for id_token, default value is client id. Developers
        MAY rewrite this method to provide a customized audience value.
        """
        client = request.client
        return [client.get_client_id()]

    def process_token(self, grant, token):
        scope = token.get('scope')
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            return token

        request = grant.request
        credential = request.credential

        config = self.get_jwt_config(grant)
        config['aud'] = self.get_audiences(request)
        config['nonce'] = credential.get_nonce()
        config['auth_time'] = credential.get_auth_time()

        user_info = self.generate_user_info(request.user, token['scope'])
        id_token = generate_id_token(token, user_info, **config)
        token['id_token'] = id_token
        return token

    def validate_openid_authorization_request(self, grant):
        validate_nonce(grant.request, self.exists_nonce, self.require_nonce)

    def __call__(self, grant):
        grant.register_hook('process_token', self.process_token)
        if is_openid_scope(grant.request.scope):
            grant.register_hook(
                'after_validate_authorization_request',
                self.validate_openid_authorization_request
            )
            grant.register_hook(
                'after_validate_consent_request',
                validate_request_prompt
            )


class OpenIDCodeGrant(grants.AuthorizationCodeGrant):  # pragma: no cover
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic']

    def __init__(self, *args, **kwargs):
        deprecate('Deprecate "OpenIDCodeGrant".', '1.0', 'fjPsV', 'oi')

        super(OpenIDCodeGrant, self).__init__(*args, **kwargs)
        config = self.server.config
        extension = OpenIDCode(
            key=config['jwt_key'],
            alg=config['jwt_alg'],
            iss=config['jwt_iss'],
            exp=config['jwt_exp'],
            exists_nonce=self.exists_nonce,
        )
        extension(self)

    def exists_nonce(self, nonce, request):
        raise NotImplementedError()
