import logging
from .oauth1 import OAuth1Session
from .oauth2 import OAuth2Session
from .errors import OAuthException
from ..specs.rfc6749 import OAuth2Token
from ..common.urls import urlparse

__all__ = ['OAuthClient']

log = logging.getLogger(__name__)


class OAuthClient(object):
    def __init__(self, client_key=None, client_secret=None,
                 request_token_url=None, request_token_params=None,
                 access_token_url=None, access_token_params=None,
                 refresh_token_url=None, authorize_url=None,
                 api_base_url=None, client_kwargs=None, **kwargs):

        self.client_key = client_key
        self.client_secret = client_secret
        self.request_token_url = request_token_url
        self.request_token_params = request_token_params
        self.access_token_url = access_token_url
        self.access_token_params = access_token_params
        self.refresh_token_url = refresh_token_url
        self.authorize_url = authorize_url
        self.api_base_url = api_base_url
        self.client_kwargs = client_kwargs or {}
        self.compliance_fix = None

        self._kwargs = kwargs
        self._sess = None

        self._hooks = {
            'access_token_getter': None,
            'request_token_getter': None,
            'request_token_setter': None,
            'authorize_redirect': None
        }

    def register_hook(self, hook_type, f):
        if hook_type not in self._hooks:
            raise ValueError('Hook type %s is not in %s.',
                             hook_type, self._hooks)
        self._hooks[hook_type] = f

    def authorize_redirect(self, callback_uri=None, **kwargs):
        redirect = self._hooks['authorize_redirect']
        assert callable(redirect), 'missing authorize_redirect'

        if self.request_token_url:
            set_token = self._hooks['request_token_setter']
            assert callable(set_token), 'missing request_token_setter'

            sess = OAuth1Session(
                self.client_key,
                client_secret=self.client_secret,
                callback_uri=callback_uri,
                **self.client_kwargs
            )
            token = sess.fetch_request_token(
                self.request_token_url,
                **self.request_token_params
            )
            # remember oauth_token, oauth_token_secret
            set_token(token)
            url = sess.authorization_url(self.authorize_url,  **kwargs)
            state = None
        else:
            sess = OAuth2Session(
                self.client_key,
                client_secret=self.client_secret,
                redirect_uri=callback_uri,
                **self.client_kwargs
            )
            url, state = sess.authorization_url(self.authorize_url, **kwargs)
        return redirect(url, callback_uri, state)

    def authorize_access_token(self, callback_uri=None, **params):
        if self.request_token_url:
            get_request_token = self._hooks['request_token_getter']
            assert callable(get_request_token), 'missing request_token_getter'

            sess = OAuth1Session(
                self.client_key,
                client_secret=self.client_secret,
                callback_uri=callback_uri,
                **self.client_kwargs
            )
            sess.token = get_request_token()
            # re-assign token with verifier
            sess.token = params
            kwargs = self.access_token_params or {}
            token = sess.fetch_access_token(self.access_token_url, **kwargs)
        else:
            sess = OAuth2Session(
                self.client_key,
                client_secret=self.client_secret,
                redirect_uri=callback_uri,
                **self.client_kwargs
            )
            kwargs = {}
            if self.access_token_params:
                kwargs.update(self.access_token_params)
            kwargs.update(params)
            token = sess.fetch_access_token(self.access_token_url, **kwargs)
        return token

    @property
    def session(self):
        """OAuth 1/2 Session for requests. Initialized lazily."""
        if self._sess:
            return self._sess

        if self.request_token_url:
            self._sess = OAuth1Session(
                self.client_key, self.client_secret, **self.client_kwargs)
        else:
            self._sess = OAuth2Session(
                self.client_key, self.client_secret, **self.client_kwargs)
            # only OAuth2 has compliance_fix currently
            if self.compliance_fix:
                self.compliance_fix(self._sess)
        return self._sess

    def set_token(self, token):
        if not self.request_token_url and isinstance(token, dict):
            token = OAuth2Token(token)
        self.session.token = token

    def _get_access_token(self):
        func = self._hooks['access_token_getter']
        assert callable(func), 'missing access_token_getter'
        rv = func()
        if rv is None:
            raise OAuthException('No token available', type='token_missing')
        return rv

    def request(self, method, url, **kwargs):
        if self.api_base_url and not url.startswith(('https://', 'http://')):
            url = urlparse.urljoin(self.api_base_url, url)
        if not self.session.token:
            self.set_token(self._get_access_token())
        return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)
