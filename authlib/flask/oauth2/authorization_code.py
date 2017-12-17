from authlib.common.security import generate_token
from authlib.specs.rfc6749.grants import AuthorizationCodeGrant
from ..cache import Cache


class AuthorizationCode(dict):
    def __getattr__(self, key):
        if key in self:
            return self[key]
        raise AttributeError()


def register_cache_authorization_code(
        app, authorization_server,
        create_access_token, get_user_id=None):
    """Use cache for authorization code grant endpoint.

    :param app: Flask app instance.
    :param authorization_server: AuthorizationServer instance.
    :param create_access_token: A function to create access_token.
    :param get_user_id: A function to get user's ID.
    """

    cache = Cache(app, config_prefix='OAUTH2_CODE')
    key_tpl = 'oauth2_authorization_code:{}_{}'

    class CodeGrant(AuthorizationCodeGrant):
        def create_authorization_code(self, client, user, **kwargs):
            code = generate_token(48)
            if callable(get_user_id):
                user_id = get_user_id(user)
            else:
                user_id = user.id
            data = dict(
                code=code,
                client_id=client.client_id,
                redirect_uri=kwargs.get('redirect_uri', ''),
                scope=kwargs.get('scope', ''),
                user_id=user_id,
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

    authorization_server.register_grant_endpoint(CodeGrant)

