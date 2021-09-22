import functools
from django.http import JsonResponse
from authlib.oauth2 import (
    OAuth2Error,
    ResourceProtector as _ResourceProtector,
)
from authlib.oauth2.rfc6749 import (
    MissingAuthorizationError,
    HttpRequest,
)
from authlib.oauth2.rfc6750 import (
    BearerTokenValidator as _BearerTokenValidator
)
from .signals import token_authenticated


class ResourceProtector(_ResourceProtector):
    def acquire_token(self, request, scopes=None):
        """A method to acquire current valid token with the given scope.

        :param request: Django HTTP request instance
        :param scopes: a list of scope values
        :return: token object
        """
        url = request.build_absolute_uri()
        req = HttpRequest(request.method, url, request.body, request.headers)
        req.req = request
        if isinstance(scopes, str):
            scopes = [scopes]
        token = self.validate_request(scopes, req)
        token_authenticated.send(sender=self.__class__, token=token)
        return token

    def __call__(self, scopes=None, optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(request, *args, **kwargs):
                try:
                    token = self.acquire_token(request, scopes)
                    request.oauth_token = token
                except MissingAuthorizationError as error:
                    if optional:
                        request.oauth_token = None
                        return f(request, *args, **kwargs)
                    return return_error_response(error)
                except OAuth2Error as error:
                    return return_error_response(error)
                return f(request, *args, **kwargs)
            return decorated
        return wrapper


class BearerTokenValidator(_BearerTokenValidator):
    def __init__(self, token_model, realm=None, **extra_attributes):
        self.token_model = token_model
        super(BearerTokenValidator, self).__init__(realm, **extra_attributes)

    def authenticate_token(self, token_string):
        try:
            return self.token_model.objects.get(access_token=token_string)
        except self.token_model.DoesNotExist:
            return None

    def request_invalid(self, request):
        return False


def return_error_response(error):
    body = dict(error.get_body())
    resp = JsonResponse(body, status=error.status_code)
    headers = error.get_headers()
    for k, v in headers:
        resp[k] = v
    return resp
