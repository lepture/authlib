import functools
import time

from flask import request, Response, json
from authlib.specs.rfc6749 import OAuth2Error
from authlib.specs.rfc6749 import ResourceServer as _ResourceServer


class ResourceServer(_ResourceServer):
    def __init__(self, query_token, query_token_user):
        self.query_token = query_token
        self.query_token_user = query_token_user

    def authenticate_token(self, token_string, token_type):
        if token_type.lower() == 'bearer':
            return self.query_token(token_string)

    def get_token_user(self, token):
        return self.query_token_user(token)

    def get_token_scope(self, token):
        return token.scope

    def is_token_expired(self, token):
        return token.expires_at < time.time()

    def __call__(self, scope):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    token = self.validate_request(request.headers, scope)
                    request.token = token
                except OAuth2Error as error:
                    status = error.status_code
                    body = dict(error.get_body())
                    headers = error.get_headers()
                    return Response(json.dumps(body), status=status, headers=headers)
                return f(*args, **kwargs)
            return decorated
        return wrapper
