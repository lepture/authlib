from flask import Flask
from authlib.common.security import generate_token
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from ..cache import Cache


class AuthorizationCode(dict):
    def __getattr__(self, key):
        if key in self:
            return self[key]
        raise AttributeError()

    def get_redirect_uri(self):
        return self.get('redirect_uri')

    def get_scope(self):
        return self.get('scope')


def create_authorization_code_grant(
        cache, create_access_token, key_prefix='oauth2_code:'):
    key_tpl = key_prefix + '{}_{}'

    class CodeGrant(AuthorizationCodeGrant):
        def create_authorization_code(self, client, grant_user, request):
            code = generate_token(48)
            data = dict(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user_id=grant_user.id,
            )
            key = key_tpl.format(code, client.client_id)
            cache.set(key, data, timeout=600)
            return code

        def parse_authorization_code(self, code, client):
            key = key_tpl.format(code, client.client_id)
            data = cache.get(key)
            if data:
                return AuthorizationCode(**data)

        def delete_authorization_code(self, authorization_code):
            key = key_tpl.format(
                authorization_code.code,
                authorization_code.client_id
            )
            cache.delete(key)

        def create_access_token(self, token, client, authorization_code):
            create_access_token(token, client, authorization_code)

    return CodeGrant


def register_cache_authorization_code(
        cache, authorization_server, create_access_token):
    """Use cache for authorization code grant endpoint.

    :param cache: Cache instance.
    :param authorization_server: AuthorizationServer instance.
    :param create_access_token: A function to create access_token.
    """
    if isinstance(cache, Flask):
        cache = Cache(cache, config_prefix='OAUTH2_CODE')
    authorization_server.register_grant_endpoint(
        create_authorization_code_grant(cache, create_access_token)
    )
