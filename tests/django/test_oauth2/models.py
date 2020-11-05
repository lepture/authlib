import time
from django.db.models import (
    Model,
    CharField,
    TextField,
    BooleanField,
    IntegerField,
)
from django.db.models import ForeignKey, CASCADE
from django.contrib.auth.models import User
from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import (
    ClientMixin,
    TokenMixin,
    AuthorizationCodeMixin,
)
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope


def now_timestamp():
    return int(time.time())


class Client(Model, ClientMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, unique=True, db_index=True)
    client_secret = CharField(max_length=48, blank=True)
    redirect_uris = TextField(default='')
    default_redirect_uri = TextField(blank=False, default='')
    scope = TextField(default='')
    response_type = TextField(default='')
    grant_type = TextField(default='')
    token_endpoint_auth_method = CharField(max_length=120, default='')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(scope_to_list(self.scope))
        return list_to_scope([s for s in scope.split() if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        if redirect_uri == self.default_redirect_uri:
            return True
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        allowed = self.response_type.split()
        return response_type in allowed

    def check_grant_type(self, grant_type):
        allowed = self.grant_type.split()
        return grant_type in allowed


class OAuth2Token(Model, TokenMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, db_index=True)
    token_type = CharField(max_length=40)
    access_token = CharField(max_length=255, unique=True, null=False)
    refresh_token = CharField(max_length=255, db_index=True)
    scope = TextField(default='')
    revoked = BooleanField(default=False)
    issued_at = IntegerField(null=False, default=now_timestamp)
    expires_in = IntegerField(null=False, default=0)

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_revoked(self):
        return self.revoked

    def is_expired(self):
        if not self.expires_in:
            return False

        expires_at = self.issued_at + self.expires_in
        return expires_at < time.time()

    def is_refresh_token_active(self):
        if self.revoked:
            return False

        expired_at = self.issued_at + self.expires_in * 2
        return expired_at >= time.time()


class OAuth2Code(Model, AuthorizationCodeMixin):
    user = ForeignKey(User, on_delete=CASCADE)
    client_id = CharField(max_length=48, db_index=True)
    code = CharField(max_length=120, unique=True, null=False)
    redirect_uri = TextField(default='', null=True)
    response_type = TextField(default='')
    scope = TextField(default='', null=True)
    auth_time = IntegerField(null=False, default=now_timestamp)

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope or ''

    def get_auth_time(self):
        return self.auth_time


class CodeGrantMixin(object):
    def query_authorization_code(self, code, client):
        try:
            item = OAuth2Code.objects.get(code=code, client_id=client.client_id)
        except OAuth2Code.DoesNotExist:
            return None

        if not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


def generate_authorization_code(client, grant_user, request, **extra):
    code = generate_token(48)
    item = OAuth2Code(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        response_type=request.response_type,
        scope=request.scope,
        user=grant_user,
        **extra
    )
    item.save()
    return code
