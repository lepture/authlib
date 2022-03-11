"""Implementation of authlib.oauth2.rfc6749.ResourceProtector class for FastAPI."""

import functools
from contextlib import contextmanager

from authlib.oauth2 import OAuth2Error
from authlib.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import HttpRequest, MissingAuthorizationError
from fastapi import HTTPException


class ResourceProtector(_ResourceProtector):
    """ResourceProtector class."""

    def acquire_token(self, request=None, scope=None):
        """A method to acquire current valid token with the given scope.

        :param request: request object
        :param scope: string or list of scope values
        :return: token object
        """
        http_request = HttpRequest(request.method, request.url, {}, request.headers)
        token = self.validate_request(scope, http_request)
        request.state.token = token
        return token

    @contextmanager
    def acquire(self, request=None, scope=None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead."""
        try:
            yield self.acquire_token(request, scope)
        except OAuth2Error as error:
            raise_error_response(error)

    def __call__(self, scope=None, optional=False):
        def wrapper(func):
            @functools.wraps(func)
            def decorated(request, *args, **kwargs):
                try:
                    self.acquire_token(request, scope)
                except MissingAuthorizationError as error:
                    if optional:
                        return func(request, *args, **kwargs)
                    raise_error_response(error)
                except OAuth2Error as error:
                    raise_error_response(error)
                return func(request, *args, **kwargs)

            return decorated

        return wrapper


def raise_error_response(error):
    """Raise the FastAPI HTTPException method."""
    status = error.status_code
    body = dict(error.get_body())
    headers = error.get_headers()
    raise HTTPException(status_code=status, detail=body, headers=dict(headers))
