import functools
from flask import g, request, Response, json
from werkzeug.local import LocalProxy
from authlib.specs.rfc6749 import OAuth2Error
from authlib.specs.rfc6749 import ResourceProtector as _ResourceProtector
from authlib.specs.rfc6750 import BearerTokenValidator as _BearerValidator


class BearerTokenValidator(_BearerValidator):
    def request_invalid(self, method, uri, body, headers):
        return False

    def token_revoked(self, token):
        return False


class ResourceProtector(_ResourceProtector):
    def __init__(self, query_token, realm=None, validator_cls=None):
        self.query_token = query_token
        if validator_cls is None:
            validator_cls = BearerTokenValidator
        self.token_validator = validator_cls(realm)

    def authenticate_token(self, token_string, token_type):
        if token_type.lower() == 'bearer':
            # only bearer token (rfc6750) implemented
            return self.query_token(token_string)

    def __call__(self, scope=None):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    token = self.validate_request(
                        scope, request.method, request.full_path,
                        request.data, request.headers
                    )
                    g._oauth2_token_ = token
                except OAuth2Error as error:
                    status = error.status_code
                    body = dict(error.get_body())
                    headers = error.get_headers()
                    return Response(json.dumps(body), status=status, headers=headers)
                return f(*args, **kwargs)
            return decorated
        return wrapper


def _get_current_token():
    return getattr(g, '_oauth2_token_', None)


current_token = LocalProxy(_get_current_token)
