from authlib.deprecate import deprecate
from authlib.common.urls import (
    urlparse, extract_params, url_decode,
    parse_http_list, parse_keqv_list,
)
from .signature import (
    SIGNATURE_TYPE_QUERY,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_HEADER
)
from .errors import (
    InsecureTransportError,
    DuplicatedOAuthProtocolParameterError
)
from .util import unescape


class OAuth1Request(object):
    def __init__(self, method, uri, body=None, headers=None):
        InsecureTransportError.check(uri)
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers or {}

        # states namespaces
        self.client = None
        self.credential = None
        self.user = None

        self.query = urlparse.urlparse(uri).query
        self.query_params = url_decode(self.query)
        self.body_params = extract_params(body) or []

        auth = headers.get('Authorization')
        self.realm = None
        if auth:
            self.auth_params = _parse_authorization_header(auth)
            self.realm = dict(self.auth_params).get('realm')
        else:
            self.auth_params = []

        oauth_params_set = [
            (SIGNATURE_TYPE_QUERY, list(_filter_oauth(self.query_params))),
            (SIGNATURE_TYPE_BODY, list(_filter_oauth(self.body_params))),
            (SIGNATURE_TYPE_HEADER, list(_filter_oauth(self.auth_params)))
        ]
        oauth_params_set = [params for params in oauth_params_set if params[1]]
        if len(oauth_params_set) > 1:
            found_types = [p[0] for p in oauth_params_set]
            raise DuplicatedOAuthProtocolParameterError(
                '"oauth_" params must come from only 1 signature type '
                'but were found in {}'.format(','.join(found_types))
            )

        if oauth_params_set:
            self.signature_type = oauth_params_set[0][0]
            self.oauth_params = dict(oauth_params_set[0][1])
        else:
            self.signature_type = None
            self.oauth_params = {}

        params = []
        params.extend(self.query_params)
        params.extend(self.body_params)
        params.extend(self.auth_params)
        self.params = params

    @property
    def grant_user(self):  # pragma: no cover
        deprecate('Use "request.user" instead.', '0.8')
        return self.user

    @grant_user.setter
    def grant_user(self, user):  # pragma: no cover
        deprecate('Use "request.user" instead.', '0.8')
        self.user = user

    @property
    def client_id(self):
        return self.oauth_params.get('oauth_consumer_key')

    @property
    def client_secret(self):
        if self.client:
            return self.client.get_client_secret()

    @property
    def rsa_public_key(self):
        if self.client:
            return self.client.get_rsa_public_key()

    @property
    def timestamp(self):
        return self.oauth_params.get('oauth_timestamp')

    @property
    def redirect_uri(self):
        return self.oauth_params.get('oauth_callback')

    @property
    def signature(self):
        return self.oauth_params.get('oauth_signature')

    @property
    def signature_method(self):
        return self.oauth_params.get('oauth_signature_method')

    @property
    def token(self):
        return self.oauth_params.get('oauth_token')

    @property
    def token_secret(self):
        if self.credential:
            return self.credential.get_oauth_token_secret()


def _filter_oauth(params):
    for k, v in params:
        if k.startswith('oauth_'):
            yield (k, v)


def _parse_authorization_header(authorization_header):
    """Parse an OAuth authorization header into a list of 2-tuples"""
    auth_scheme = 'oauth '
    if authorization_header.lower().startswith(auth_scheme):
        items = parse_http_list(authorization_header[len(auth_scheme):])
        try:
            items = parse_keqv_list(items).items()
            return [(unescape(k), unescape(v)) for k, v in items]
        except (IndexError, ValueError):
            pass
    raise ValueError('Malformed authorization header')
