import functools
from flask import g, json, Response
from flask import request as _req
from werkzeug.local import LocalProxy
from authlib.specs.rfc5849 import OAuth1Error
from authlib.specs.rfc5849 import ResourceProtector as _ResourceProtector
from ..cache import Cache

_JSON_HEADERS = [
    ('Content-Type', 'application/json'),
    ('Cache-Control', 'no-store'),
    ('Pragma', 'no-cache'),
]


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Initialize a resource
    protector with the query_token method::

        from authlib.flask.oauth1 import ResourceProtector, current_credential
        from your_project.models import Token, User, cache

        # you need to define a ``cache`` instance yourself

        def query_token(client_id, oauth_token):
            return Token.query.filter_by(
                client_id=client_id, oauth_token=oauth_token
            ).first()

        require_oauth= ResourceProtector(
            app, client_model=OAuth1Client,
            cache=cache, query_token=query_token
        )
        # or initialize it lazily
        require_oauth = ResourceProtector()
        require_oauth.init_app(
            app, client_model=OAuth1Client,
            cache=cache, query_token=query_token
        )
    """
    def __init__(self, app=None, client_model=None, cache=None,
                 query_token=None, exists_nonce=None):
        super(ResourceProtector, self).__init__(client_model)
        self._query_token = query_token
        self._exists_nonce = exists_nonce
        self.cache = cache
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

        if app.config.get('OAUTH1_RESOURCE_CACHE_TYPE'):
            self.cache = Cache(app, config_prefix='OAUTH1_RESOURCE')
        elif cache:
            self.cache = cache

        methods = app.config.get('OAUTH1_SUPPORTED_SIGNATURE_METHODS')
        if methods and isinstance(methods, (list, tuple)):
            self.SUPPORTED_SIGNATURE_METHODS = methods

        self.app = app

    def get_token_credential(self, request):
        return self._query_token(request.client_id, request.token)

    def _exists_cache_nonce(self, nonce, timestamp, client_id, token):
        key = 'nonce:{}-{}-{}'.format(nonce, timestamp, client_id)
        if token:
            key = '{}-{}'.format(key, token)
        rv = self.cache.has(key)
        self.cache.set(key, 1, timeout=self.EXPIRY_TIME)
        return rv

    def exists_nonce(self, nonce, request):
        func = self._exists_nonce
        if func is None and self.cache:
            func = self._exists_cache_nonce

        if callable(func):
            timestamp = request.timestamp
            client_id = request.client_id
            token = request.token
            return func(nonce, timestamp, client_id, token)

        raise RuntimeError('"exists_nonce" is not implemented.')

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
