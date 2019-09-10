import json
from django.http import HttpResponse
from django.utils.module_loading import import_string
from django.conf import settings
from authlib.oauth2 import (
    OAuth2Request,
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6750 import BearerToken
from authlib.common.security import generate_token as _generate_token
from .signals import client_authenticated, token_revoked
from ..helpers import create_oauth_request


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, client_model, token_model, generate_token=None, metadata=None):
        self.config = getattr(settings, 'AUTHLIB_OAUTH2_PROVIDER', {})
        self.client_model = client_model
        self.token_model = token_model
        if generate_token is None:
            generate_token = self.create_bearer_token_generator()

        super(AuthorizationServer, self).__init__(
            query_client=self.get_client_by_id,
            save_token=self.save_oauth2_token,
            generate_token=generate_token,
            metadata=metadata,
        )

    def get_client_by_id(self, client_id):
        try:
            return self.client_model.objects.get(client_id=client_id)
        except self.client_model.DoesNotExist:
            return None

    def save_oauth2_token(self, token, request):
        client = request.client
        if request.user:
            user_id = request.user.pk
        else:
            user_id = client.user_id
        item = self.token_model(
            client_id=client.client_id,
            user_id=user_id,
            **token
        )
        item.save()
        return item

    def create_oauth2_request(self, request):
        return create_oauth_request(request, OAuth2Request)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        resp = HttpResponse(payload, status=status_code)
        for k, v in headers:
            resp[k] = v
        return resp

    def send_signal(self, name, *args, **kwargs):
        if name == 'after_authenticate_client':
            client_authenticated.send(sender=self.__class__, *args, **kwargs)
        elif name == 'after_revoke_token':
            token_revoked.send(sender=self.__class__, *args, **kwargs)

    def create_bearer_token_generator(self):
        conf = self.config.get('access_token_generator', True)
        access_token_generator = create_token_generator(conf, 42)

        conf = self.config.get('refresh_token_generator', False)
        refresh_token_generator = create_token_generator(conf, 48)

        conf = self.config.get('token_expires_in')
        expires_generator = create_token_expires_in_generator(conf)

        return BearerToken(
            access_token_generator=access_token_generator,
            refresh_token_generator=refresh_token_generator,
            expires_generator=expires_generator,
        )

    def get_consent_grant(self, request):
        grant = self.get_authorization_grant(request)
        grant.validate_consent_request()
        if not hasattr(grant, 'prompt'):
            grant.prompt = None
        return grant

    def validate_consent_request(self, request, end_user=None):
        req = self.create_oauth2_request(request)
        req.user = end_user
        return self.get_consent_grant(req)


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:
        def token_generator(*args, **kwargs):
            return _generate_token(length)
        return token_generator


def create_token_expires_in_generator(expires_in_conf=None):
    data = {}
    data.update(BearerToken.GRANT_TYPES_EXPIRES_IN)
    if expires_in_conf:
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

    return expires_in
