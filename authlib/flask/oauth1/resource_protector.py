import functools
from flask import g, json, Response
from flask import request as _req
from werkzeug.local import LocalProxy
from authlib.specs.rfc5849 import OAuth1Error
from authlib.specs.rfc5849 import ResourceProtector as _ResourceProtector

_JSON_HEADERS = [
    ('Content-Type', 'application/json'),
    ('Cache-Control', 'no-store'),
    ('Pragma', 'no-cache'),
]


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Initialize a resource
    protector with the query_token method::

        from authlib.flask.oauth1 import ResourceProtector, current_credential
        from authlib.flask.oauth1.cache import create_exists_nonce_func
        from your_project.models import Token, User, cache

        # you need to define a ``cache`` instance yourself

        def query_token(client_id, oauth_token):
            return Token.query.filter_by(
                client_id=client_id, oauth_token=oauth_token
            ).first()

        require_oauth= ResourceProtector(
            app, client_model=OAuth1Client,
            query_token=query_token,
            exists_nonce=create_exists_nonce_func(cache)
        )
        # or initialize it lazily
        require_oauth = ResourceProtector()
        require_oauth.init_app(
            app, client_model=OAuth1Client,
            query_token=query_token,
            create_exists_nonce_func(cache)
        )
    """
    def __init__(self, app=None, client_model=None,
                 query_token=None, exists_nonce=None):
        super(ResourceProtector, self).__init__(client_model)
        self._query_token = query_token
        self._exists_nonce = exists_nonce

        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app, client_model=None, cache=None,
                 query_token=None, exists_nonce=None):
        if client_model is not None:
            self.client_model = client_model
        if query_token is not None:
            self._query_token = query_token
        if exists_nonce is not None:
            self._exists_nonce = exists_nonce

        methods = app.config.get('OAUTH1_SUPPORTED_SIGNATURE_METHODS')
        if methods and isinstance(methods, (list, tuple)):
            self.SUPPORTED_SIGNATURE_METHODS = methods

        self.app = app

    def get_token_credential(self, request):
        return self._query_token(request.client_id, request.token)

    def exists_nonce(self, nonce, request):
        if not self._exists_nonce:
            raise RuntimeError('"exists_nonce" function is required.')

        timestamp = request.timestamp
        client_id = request.client_id
        token = request.token
        return self._exists_nonce(nonce, timestamp, client_id, token)

    def __call__(self, scope=None):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    req = self.validate_request(
                        _req.method,
                        _req.url,
                        _req.form.to_dict(flat=True),
                        _req.headers
                    )
                    g._oauth1_credential_ = req.credential
                except OAuth1Error as error:
                    body = dict(error.get_body())
                    return Response(
                        json.dumps(body),
                        status=error.status_code,
                        headers=_JSON_HEADERS
                    )
                return f(*args, **kwargs)
            return decorated
        return wrapper


def _get_current_credential():
    return getattr(g, '_oauth1_credential_', None)


current_credential = LocalProxy(_get_current_credential)
