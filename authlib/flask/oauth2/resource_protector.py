import functools
from flask import g, request, Response, json
from werkzeug.local import LocalProxy
from authlib.specs.rfc6749 import OAuth2Error
from authlib.specs.rfc6749 import ResourceProtector as _ResourceProtector
from authlib.specs.rfc6750 import BearerTokenValidator as _BearerValidator


class BearerTokenValidator(_BearerValidator):
    """A default Bearer token validator. Simple but ready to use."""

    def request_invalid(self, method, uri, body, headers):
        """Validate if current HTTP request is valid. It always return ``False``.
        Developers who want to validate the HTTP request can re-implement it
        with :class:`authlib.specs.rfc6750.BearerTokenValidator`.
        """
        return False

    def token_revoked(self, token):
        """Validate if current token is revoked. It always return ``False``.
        Developers who want to validate token revoked can re-implement it
        with :class:`authlib.specs.rfc6750.BearerTokenValidator`.
        """
        return False


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Initialize a resource
    protector with the query_token method::

        from authlib.flask.oauth2 import ResourceProtector, current_token
        from your_project.models import Token, User

        def query_token(cls, access_token):
            return Token.query.filter_by(access_token=access_token).first()

        require_oauth= ResourceProtector(query_token)

        @app.route('/user')
        @require_oauth('profile')
        def user_profile():
            user = User.query.get(current_token.user_id)
            return jsonify(user.to_dict())

    :param query_token: a function to query token model by access_token string.
    :param realm: a string to represent realm value. Default is ``None``.
    :param validator_cls: a token validator class. Default is
        :class:`authlib.flask.oauth2.BearerTokenValidator`.
    """
    def __init__(self, query_token, realm=None, validator_cls=None):
        self.query_token = query_token
        if validator_cls is None:
            validator_cls = BearerTokenValidator
        self.token_validator = validator_cls(realm)

    def authenticate_token(self, token_string, token_type):
        """Authenticate token in Authorization header. Only Bearer Token is
        supported for now.
        """
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
