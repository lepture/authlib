from authlib.common.security import generate_token
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.deprecate import deprecate

deprecate('Removed "authlib.flask.oauth2.cache"', '1.0', 'Jeclj', 'sq')


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
        cache, authenticate_user, key_prefix='oauth2_code:'):
    key_tpl = key_prefix + '{}_{}'

    class CodeGrant(AuthorizationCodeGrant):
        def create_authorization_code(self, client, grant_user, request):
            code = generate_token(48)
            data = dict(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user_id=grant_user.get_user_id(),
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

        def authenticate_user(self, authorization_code):
            return authenticate_user(authorization_code)

    return CodeGrant


def register_cache_authorization_code(
        cache, authorization_server, authenticate_user):
    """Use cache for authorization code grant endpoint.

    :param cache: Cache instance.
    :param authorization_server: AuthorizationServer instance.
    :param authenticate_user: A function to authenticate user.
    """
    grant_cls = create_authorization_code_grant(cache, authenticate_user)
    authorization_server.register_grant(grant_cls)
