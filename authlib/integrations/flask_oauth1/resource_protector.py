import functools
from flask import json, Response
from flask import request as _req
from flask import _app_ctx_stack
from werkzeug.local import LocalProxy
from authlib.consts import default_json_headers
from authlib.oauth1 import ResourceProtector as _ResourceProtector
from authlib.oauth1.errors import OAuth1Error


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Initialize a resource
    protector with the query_token method::

        from authlib.integrations.flask_oauth1 import ResourceProtector, current_credential
        from authlib.integrations.flask_oauth1 import create_exists_nonce_func
        from authlib.integrations.sqla_oauth1 import (
            create_query_client_func,
            create_query_token_func,
        )
        from your_project.models import Token, User, cache

        # you need to define a ``cache`` instance yourself

        require_oauth= ResourceProtector(
            app,
            query_client=create_query_client_func(db.session, OAuth1Client),
            query_token=create_query_token_func(db.session, OAuth1Token),
            exists_nonce=create_exists_nonce_func(cache)
        )
        # or initialize it lazily
        require_oauth = ResourceProtector()
        require_oauth.init_app(
            app,
            query_client=create_query_client_func(db.session, OAuth1Client),
            query_token=create_query_token_func(db.session, OAuth1Token),
            exists_nonce=create_exists_nonce_func(cache)
        )
    """
    def __init__(self, app=None, query_client=None,
                 query_token=None, exists_nonce=None):
        self.query_client = query_client
        self.query_token = query_token
        self._exists_nonce = exists_nonce

        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app, query_client=None, query_token=None,
                 exists_nonce=None):
        if query_client is not None:
            self.query_client = query_client
        if query_token is not None:
            self.query_token = query_token
        if exists_nonce is not None:
            self._exists_nonce = exists_nonce

        methods = app.config.get('OAUTH1_SUPPORTED_SIGNATURE_METHODS')
        if methods and isinstance(methods, (list, tuple)):
            self.SUPPORTED_SIGNATURE_METHODS = methods

        self.app = app

    def get_client_by_id(self, client_id):
        return self.query_client(client_id)

    def get_token_credential(self, request):
        return self.query_token(request.client_id, request.token)

    def exists_nonce(self, nonce, request):
        if not self._exists_nonce:
            raise RuntimeError('"exists_nonce" function is required.')

        timestamp = request.timestamp
        client_id = request.client_id
        token = request.token
        return self._exists_nonce(nonce, timestamp, client_id, token)

    def acquire_credential(self):
        req = self.validate_request(
            _req.method,
            _req.url,
            _req.form.to_dict(flat=True),
            _req.headers
        )
        ctx = _app_ctx_stack.top
        ctx.authlib_server_oauth1_credential = req.credential
        return req.credential

    def __call__(self, scope=None):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    self.acquire_credential()
                except OAuth1Error as error:
                    body = dict(error.get_body())
                    return Response(
                        json.dumps(body),
                        status=error.status_code,
                        headers=default_json_headers,
                    )
                return f(*args, **kwargs)
            return decorated
        return wrapper


def _get_current_credential():
    ctx = _app_ctx_stack.top
    return getattr(ctx, 'authlib_server_oauth1_credential', None)


current_credential = LocalProxy(_get_current_credential)
