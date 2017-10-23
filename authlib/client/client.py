import logging
from .oauth1 import OAuth1Session
from .oauth2 import OAuth2Session
from .errors import OAuthException
from ..common.urls import urlparse

log = logging.getLogger(__name__)


class OAuthClient(object):
    def __init__(self, client_key=None, client_secret=None,
                 request_token_url=None, request_token_params=None,
                 access_token_url=None, access_token_params=None,
                 refresh_token_url=None, authorize_url=None,
                 api_base_url=None):

        self.client_key = client_key
        self.client_secret = client_secret
        self.request_token_url = request_token_url
        self.request_token_params = request_token_params
        self.access_token_url = access_token_url
        self.access_token_params = access_token_params
        self.refresh_token_url = refresh_token_url
        self.authorize_url = authorize_url
        self.api_base_url = api_base_url

        self._sess = None

        self._hooks = {
            'access_token_getter': None,
            'access_token_setter': None,
            'request_token_getter': None,
            'request_token_setter': None,
            'redirect_uri_setter': None,
            'redirect_uri_getter': None,
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
            )
            token = sess.fetch_request_token(
                self.request_token_url,
                **self.request_token_params
            )
            # remember oauth_token, oauth_token_secret
            set_token(token)
            url, state = sess.authorization_url(self.authorize_url)
        else:
            sess = OAuth2Session(
                self.client_key,
                client_secret=self.client_secret,
                redirect_uri=callback_uri,
            )
            url, state = sess.authorization_url(self.authorize_url)
        return redirect(url, state)

    def authorize_access_token(self, params):
        set_access_token = self._hooks['access_token_setter']
        assert callable(set_access_token), 'missing access_token_setter'

        if self.request_token_url:
            get_request_token = self._hooks['request_token_getter']
            assert callable(get_request_token), 'missing request_token_getter'

            token = get_request_token()
            sess = OAuth1Session(
                self.client_key,
                client_secret=self.client_secret,
                token=token,
            )
            token = sess.fetch_access_token(self.access_token_url)
        else:
            sess = OAuth2Session(
                self.client_key,
                client_secret=self.client_secret,
            )
            token = sess.fetch_access_token(self.access_token_url)
        set_access_token(token)
        return token

    @property
    def session(self):
        if self._sess:
            return self._sess

        if self.request_token_url:
            self._sess = OAuth1Session(self.client_key, self.client_secret)
        else:
            self._sess = OAuth2Session(self.client_key, self.client_secret)

        return self._sess

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
            self.session.token = self._get_access_token()
        return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)
