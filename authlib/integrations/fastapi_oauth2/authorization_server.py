"""Implementation of authlib.oauth2.rfc6749.AuthorizationServer class for FastAPI."""

import json

from authlib.common.security import generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2 import HttpRequest, OAuth2Request
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from fastapi.responses import JSONResponse
from werkzeug.utils import import_string


class AuthorizationServer(_AuthorizationServer):
    """AuthorizationServer class."""

    def __init__(self, query_client=None, save_token=None):
        super().__init__(query_client=query_client, save_token=save_token)
        self.config = {}

    def init_app(self, app, query_client=None, save_token=None):
        """Initialize the FastAPI app."""
        if query_client is not None:
            self.query_client = query_client
        if save_token is not None:
            self.save_token = save_token

        self.generate_token = create_bearer_token_generator(app.config)

        metadata_class = AuthorizationServerMetadata

        metadata_file = app.config.get("OAUTH2_METADATA_FILE")
        if metadata_file:
            with open(metadata_file) as metadata_file_content:
                metadata = metadata_class(json.loads(metadata_file_content))
                metadata.validate()
                self.metadata = metadata

        self.config.setdefault("error_uris", app.config.get("OAUTH2_ERROR_URIS"))

    def get_error_uris(self, request):
        error_uris = self.config.get("error_uris")
        if error_uris:
            return dict(error_uris)
        return None

    def create_oauth2_request(self, request):
        return OAuth2Request(
            request.method, str(request.url), request.body, request.headers
        )

    def create_json_request(self, request):
        return HttpRequest(
            request.method, str(request.url), request.body, request.headers
        )

    def handle_response(self, status, body, headers):
        return JSONResponse(content=body, status_code=status, headers=dict(headers))

    def validate_consent_request(self, request=None, end_user=None):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization"""
        req = self.create_oauth2_request(request)
        req.user = end_user

        grant = self.get_authorization_grant(req)
        grant.validate_consent_request()
        if not hasattr(grant, "prompt"):
            grant.prompt = None
        return grant


def create_bearer_token_generator(config):
    """Create a generator function for generating ``token`` value. This
    method will create a Bearer Token generator with
    :class:`authlib.oauth2.rfc6750.BearerToken`. By default, it will not
    generate ``refresh_token``, which can be turn on by configuration
    ``OAUTH2_REFRESH_TOKEN_GENERATOR=True``.
    """
    conf = config.get("OAUTH2_ACCESS_TOKEN_GENERATOR", True)
    access_token_generator = create_token_generator(conf, 42)

    conf = config.get("OAUTH2_REFRESH_TOKEN_GENERATOR", False)
    refresh_token_generator = create_token_generator(conf, 48)

    expires_generator = create_token_expires_in_generator(config)

    return BearerToken(
        access_token_generator, refresh_token_generator, expires_generator
    )


def create_token_expires_in_generator(config):
    """Create a generator function for generating ``expires_in`` value.
    Developers can re-implement this method with a subclass if other means
    required. The default expires_in value is defined by ``grant_type``,
    different ``grant_type`` has different value. It can be configured
    with::

        OAUTH2_TOKEN_EXPIRES_IN = {
            'authorization_code': 864000
        }
    """
    data = {}
    data.update(BearerToken.GRANT_TYPES_EXPIRES_IN)

    expires_in_conf = config.get("OAUTH2_TOKEN_EXPIRES_IN")
    if expires_in_conf:
        data.update(expires_in_conf)

    def expires_in(client, grant_type):  # pylint: disable=W0613
        return data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    """Create a token generator function."""
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)

    if token_generator_conf is True:

        def token_generator(*args, **kwargs):  # pylint: disable=W0613
            return generate_token(length)

        return token_generator

    return None
