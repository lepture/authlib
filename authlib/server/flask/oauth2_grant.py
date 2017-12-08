from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    ImplicitGrant as _ImplicitGrant,
    ResourceOwnerPasswordCredentialsGrant as _PasswordCredentialsGrant,
    ClientCredentialsGrant as _ClientCredentialsGrant,
)


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    authorization_code_model = None
    authorization_code_cache = None
    token_model = None
    token_generator = None

    @property
    def authorization_code_factory(self):
        if self.authorization_code_cache is not None:
            return self.authorization_code_cache
        if self.authorization_code_model is not None:
            return self.authorization_code_model

    def create_authorization_code(self, client, user, **kwargs):
        item = self.authorization_code_factory.create_authorization_code(
            client, user, **kwargs
        )
        return item.code

    def parse_authorization_code(self, client, code):
        return self.authorization_code_factory.parse_authorization_code(
            client, code
        )

    def create_access_token(self, client, authorization_code):
        token = self.token_generator(
            grant_type=self.GRANT_TYPE,
            scope=authorization_code.scope
        )
        self.token_model.create_access_token(
            client=client,
            token=token,
            user=authorization_code.get_authorization_code_user(),
            grant_type=self.GRANT_TYPE,
        )
        raise NotImplementedError()


class ImplicitGrant(_ImplicitGrant):
    token_model = None
    token_generator = None

    def create_access_token(self, client, grant_user, **kwargs):
        token = self.token_generator(
            grant_type=self.GRANT_TYPE,
            scope=kwargs.get('scope', '')
        )
        self.token_model.create_access_token(
            client=client,
            token=token,
            user=grant_user,
            grant_type=self.GRANT_TYPE,
        )
        raise NotImplementedError()


class ResourceOwnerPasswordCredentialsGrant(_PasswordCredentialsGrant):
    def authenticate_user(self):
        raise NotImplementedError()

    def create_access_token(self, client, user, **kwargs):
        raise NotImplementedError()


class ClientCredentialsGrant(_ClientCredentialsGrant):
    def create_access_token(self, client):
        raise NotImplementedError()
