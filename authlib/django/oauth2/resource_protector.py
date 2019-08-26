import functools
from django.http import JsonResponse
from authlib.oauth2 import (
    OAuth2Error,
    ResourceProtector as _ResourceProtector
)
from authlib.oauth2.rfc6749 import (
    MissingAuthorizationError,
    TokenRequest,
)
from .signals import token_authenticated
from ..helpers import parse_request_headers


class ResourceProtector(_ResourceProtector):
    def return_error_response(self, error):
        """Raise HTTPException for OAuth2Error. Developers can re-implement
        this method to customize the error response.

        :param error: OAuth2Error
        :raise: HTTPException
        """
        body = dict(error.get_body())
        resp = JsonResponse(body, status=error.status_code)
        headers = error.get_headers()
        for k, v in headers:
            resp[k] = v
        return resp

    def acquire_token(self, request, scope=None, operator='AND'):
        """A method to acquire current valid token with the given scope.

        :param request: Django HTTP request instance
        :param scope: string or list of scope values
        :param operator: value of "AND" or "OR"
        :return: token object
        """
        headers = parse_request_headers(request)
        url = request.get_raw_uri()
        req = TokenRequest(request.method, url, request.body, headers)
        if not callable(operator):
            operator = operator.upper()
        token = self.validate_request(scope, req, operator)
        token_authenticated.send(sender=self.__class__, token=token)
        return token

    def __call__(self, scope=None, operator='AND', optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(request, *args, **kwargs):
                try:
                    token = self.acquire_token(request, scope, operator)
                    request.oauth_token = token
                except MissingAuthorizationError as error:
                    if optional:
                        return f(*args, **kwargs)
                    return self.return_error_response(error)
                except OAuth2Error as error:
                    return self.return_error_response(error)
                return f(*args, **kwargs)
            return decorated
        return wrapper
