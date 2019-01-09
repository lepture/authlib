# -*- coding: utf-8 -*-
from authlib.common.urls import (
    url_decode,
    add_params_to_uri,
    urlparse,
)
from authlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_TYPE_HEADER,
)
from .errors import (
    MissingTokenError,
    MissingVerifierError,
)
from .oauth1_auth import OAuth1Auth


class OAuth1Protocol(object):
    def __init__(self, client_id, client_secret=None,
                 token=None, token_secret=None,
                 redirect_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 force_include_body=False, **kwargs):
        if not client_id:
            raise ValueError('Missing "client_id"')

        self._client = OAuth1Auth(
            client_id, client_secret=client_secret,
            token=token,
            token_secret=token_secret,
            redirect_uri=redirect_uri,
            signature_method=signature_method,
            signature_type=signature_type,
            rsa_key=rsa_key,
            verifier=verifier,
            force_include_body=force_include_body
        )
        self.auth = self._client
        self._kwargs = kwargs

    @property
    def redirect_uri(self):
        return self._client.redirect_uri

    @redirect_uri.setter
    def redirect_uri(self, uri):
        self._client.redirect_uri = uri

    @property
    def token(self):
        return dict(
            oauth_token=self._client.token,
            oauth_token_secret=self._client.token_secret,
            oauth_verifier=self._client.verifier
        )

    @token.setter
    def token(self, token):
        """This token setter is designed for an easy integration for
        OAuthClient. Make sure both OAuth1Session and OAuth2Session
        have token setters.
        """
        if token is None:
            self._client.token = None
            self._client.token_secret = None
            self._client.verifier = None
        elif 'oauth_token' in token:
            self._client.token = token['oauth_token']
            if 'oauth_token_secret' in token:
                self._client.token_secret = token['oauth_token_secret']
            if 'oauth_verifier' in token:
                self._client.verifier = token['oauth_verifier']
        else:
            msg = 'oauth_token is missing: {!r}'.format(token)
            raise MissingTokenError(description=msg)

    def create_authorization_url(self, url, request_token=None, **kwargs):
        """Create an authorization URL by appending request_token and optional
        kwargs to url.

        This is the second step in the OAuth 1 workflow. The user should be
        redirected to this authorization URL, grant access to you, and then
        be redirected back to you. The redirection back can either be specified
        during client registration or by supplying a callback URI per request.

        :param url: The authorization endpoint URL.
        :param request_token: The previously obtained request token.
        :param kwargs: Optional parameters to append to the URL.
        :returns: The authorization URL with new parameters embedded.
        """
        kwargs['oauth_token'] = request_token or self._client.token
        if self._client.redirect_uri:
            kwargs['oauth_callback'] = self._client.redirect_uri
        return add_params_to_uri(url, kwargs.items())

    def fetch_request_token(self, url, realm=None, **kwargs):
        """Method for fetching an access token from the token endpoint.

        This is the first step in the OAuth 1 workflow. A request token is
        obtained by making a signed post request to url. The token is then
        parsed from the application/x-www-form-urlencoded response and ready
        to be used to construct an authorization url.

        :param url: Request Token endpoint.
        :param realm: A string/list/tuple of realm for Authorization header.
        :param kwargs: Extra parameters to include for fetching token.
        :return: A Request Token dict.

        Note, ``realm`` can also be configured when session created::

            session = OAuth1Session(client_id, client_secret, ..., realm='')
        """
        if realm is None:
            realm = self._kwargs.get('realm', None)
        if realm:
            if isinstance(realm, (tuple, list)):
                realm = ' '.join(realm)
            self._client.realm = realm
        else:
            self._client.realm = None

        resp = self._fetch_token(url, **kwargs)
        self._client.redirect_uri = None
        self._client.realm = None
        return resp

    def fetch_access_token(self, url, verifier=None, **kwargs):
        """Method for fetching an access token from the token endpoint.

        This is the final step in the OAuth 1 workflow. An access token is
        obtained using all previously obtained credentials, including the
        verifier from the authorization step.

        :param url: Access Token endpoint.
        :param verifier: A verifier string to prove authorization was granted.
        :param kwargs: Extra parameters to include for fetching access token.
        :return: A token dict.
        """
        if verifier:
            self._client.verifier = verifier
        if not self._client.verifier:
            raise MissingVerifierError()
        resp = self._fetch_token(url, **kwargs)
        self._client.verifier = None
        return resp

    def parse_authorization_response(self, url):
        """Extract parameters from the post authorization redirect
        response URL.

        :param url: The full URL that resulted from the user being redirected
                    back from the OAuth provider to you, the client.
        :returns: A dict of parameters extracted from the URL.
        """
        token = dict(url_decode(urlparse.urlparse(url).query))
        self.token = token
        return token

    def _fetch_token(self, url, **kwargs):
        raise NotImplementedError()
