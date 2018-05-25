import functools
from contextlib import contextmanager
from flask import request as _req
from flask import _app_ctx_stack
from werkzeug.local import LocalProxy
from authlib.specs.rfc6749 import OAuth2Error, TokenRequest
from authlib.specs.rfc6749 import ResourceProtector as _ResourceProtector
from .signals import token_authenticated
from ..error import raise_oauth2_error


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Creating a ``require_oauth``
    decorator easily with ResourceProtector::

        from authlib.flask.oauth2 import ResourceProtector

        require_oauth = ResourceProtector()

        # add bearer token validator
        from authlib.specs.rfc6750 import BearerTokenValidator
        from project.models import Token

        class MyBearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()

            def request_invalid(self, request):
                return False

            def token_revoked(self, token):
                return False

        ResourceProtector.register_token_validator(MyBearerTokenValidator())

        # protect resource with require_oauth

        @app.route('/user')
        @require_oauth('profile')
        def user_profile():
            user = User.query.get(current_token.user_id)
            return jsonify(user.to_dict())

    """
    def acquire_token(self, scope=None):
        """A method to acquire current valid token with the given scope.

        :param scope: resource scope value
        :return: token object
        """
        request = TokenRequest(
            _req.method,
            _req.full_path,
            _req.data,
            _req.headers
        )
        token = self.validate_request(scope, request)
        token_authenticated.send(self, token=token)
        ctx = _app_ctx_stack.top
        ctx.authlib_server_oauth2_token = token
        return token

    @contextmanager
    def acquire(self, scope=None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

            @app.route('/api/user')
            def user_api():
                with require_oauth.acquire('profile') as token:
                    user = User.query.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        try:
            yield self.acquire_token(scope)
        except OAuth2Error as error:
            raise_oauth2_error(error)

    def __call__(self, scope=None):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    self.acquire_token(scope)
                except OAuth2Error as error:
                    raise_oauth2_error(error)
                return f(*args, **kwargs)
            return decorated
        return wrapper


def _get_current_token():
    ctx = _app_ctx_stack.top
    return getattr(ctx, 'authlib_server_oauth2_token', None)


current_token = LocalProxy(_get_current_token)
