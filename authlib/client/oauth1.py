# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from requests import Session
from requests.auth import AuthBase
from requests.utils import to_native_string
from .errors import OAuthException
from ..common.encoding import to_unicode
from ..common.urls import (
    url_decode,
    extract_params,
    add_params_to_uri,
    urlparse,
)
from ..specs.rfc5849 import Client
from ..specs.rfc5849 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_HEADER,
)


__all__ = ['OAuth1Session', 'OAuth1']

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'


class OAuth1Session(Session):
    """Construct a new OAuth 1 client requests session.

    :param client_key: Consumer key, which you get from registration.
    :param client_secret: Consumer Secret, which you get from registration.
    :param resource_owner_key: A resource owner key, also referred to as
                               request token or access token depending on
                               when in the workflow it is used.
    :param resource_owner_secret: A resource owner secret obtained with
                                  either a request or access token. Often
                                  referred to as token secret.
    :param callback_uri: The URL the user is redirect back to after
                         authorization.
    :param rsa_key: The private RSA key as a string. Can only be used with
                    signature_method=authlib.spec.rfc5849.SIGNATURE_RSA.
    :param verifier: A verifier string to prove authorization was granted.
    :param signature_method: Signature methods for OAuth 1, available types:

                             * :data:`authlib.spec.rfc5849.SIGNATURE_HMAC_SHA1`
                             * :data:`authlib.spec.rfc5849.SIGNATURE_RSA_SHA1`
                             * :data:`authlib.spec.rfc5849.SIGNATURE_PLAINTEXT`

                             Default is ``SIGNATURE_HMAC_SHA1``. You can extend
                             signature method via ``rfc5849.Client``.
    :param signature_type: Signature type decides where the OAuth
                           parameters are added. Either in the
                           Authorization header (default) or to the URL
                           query parameters or the request body. Defined as:

                           * :data:`authlib.spec.rfc5849.SIGNATURE_TYPE_HEADER`
                           * :data:`authlib.spec.rfc5849.SIGNATURE_TYPE_BODY`
                           * :data:`authlib.spec.rfc5849.SIGNATURE_TYPE_QUERY`

    :param force_include_body: Always include the request body in the
                               signature creation.
    :param kwargs: Extra parameters to include.
    """
    def __init__(self, client_key, client_secret=None,
                 resource_owner_key=None, resource_owner_secret=None,
                 callback_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 force_include_body=False, **kwargs):
        super(OAuth1Session, self).__init__()

        self._client = OAuth1(
            client_key, client_secret=client_secret,
            resource_owner_key=resource_owner_key,
            resource_owner_secret=resource_owner_secret,
            callback_uri=callback_uri,
            signature_method=signature_method,
            signature_type=signature_type,
            rsa_key=rsa_key,
            verifier=verifier,
            force_include_body=force_include_body
        )
        self.auth = self._client
        self._kwargs = kwargs

    @property
    def callback_uri(self):
        return self._client.callback_uri

    @callback_uri.setter
    def callback_uri(self, uri):
        self._client.callback_uri = uri

    @property
    def token(self):
        return dict(
            oauth_token=self._client.resource_owner_key,
            oauth_token_secret=self._client.resource_owner_secret,
            oauth_verifier=self._client.verifier
        )

    @token.setter
    def token(self, token):
        """This token setter is designed for an easy integration for
        OAuthClient. Make sure both OAuth1Session and OAuth2Session
        have token setters.
        """
        if 'oauth_token' in token:
            self._client.resource_owner_key = token['oauth_token']
        else:
            msg = 'oauth_token is missing: {resp}'.format(resp=token)
            raise OAuthException(msg, 'token_missing', token)
        if 'oauth_token_secret' in token:
            self._client.resource_owner_secret = token['oauth_token_secret']
        if 'oauth_verifier' in token:
            self._client.verifier = token['oauth_verifier']

    def authorization_url(self, url, request_token=None, **kwargs):
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
        kwargs['oauth_token'] = request_token or self._client.resource_owner_key
        if self._client.callback_uri:
            kwargs['oauth_callback'] = self._client.callback_uri
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

            session = OAuth1Session(client_key, client_secret, ..., realm='')
        """
        if realm is None:
            realm = self._kwargs.get('realm', None)
        if realm:
            if isinstance(realm, (tuple, list)):
                realm = ' '.join(realm)
            self._client.realm = realm
        else:
            self._client.realm = None
        token = self._fetch_token(url, **kwargs)
        self._client.callback_uri = None
        self._client.realm = None
        return token

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
            raise OAuthException('No client verifier has been set.')
        token = self._fetch_token(url, **kwargs)
        self._client.verifier = None
        return token

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
        resp = self.post(url, **kwargs)

        if resp.status_code >= 400:
            error = "Token request failed with code {}, response was '{}'."
            message = error.format(resp.status_code, resp.text)
            raise OAuthException(message, 'token_request_denied', resp)

        try:
            text = resp.text.strip()
            if text.startswith('{'):
                token = json.loads(text)
            else:
                token = dict(url_decode(text))
        except (TypeError, ValueError) as e:
            error = ("Unable to decode token from token response. "
                     "This is commonly caused by an unsuccessful request where"
                     " a non urlencoded error message is returned. "
                     "The decoding error was %s""" % e)
            raise ValueError(error)

        self.token = token
        return token

    def rebuild_auth(self, prepared_request, response):
        """
        When being redirected we should always strip Authorization
        header, since nonce may not be reused as per OAuth spec.
        """
        if 'Authorization' in prepared_request.headers:
            # If we get redirected to a new host, we should strip out
            # any authentication headers.
            prepared_request.headers.pop('Authorization', True)
            prepared_request.prepare_auth(self.auth)


class OAuth1(AuthBase, Client):
    """Signs the request using OAuth 1 (RFC5849)"""

    def sign_request(self, req):
        return self.sign(req.method, req.url, req.body, req.headers)

    def __call__(self, req):
        """Add OAuth parameters to the request.

        Parameters may be included from the body if the content-type is
        urlencoded, if no content type is set a guess is made.
        """
        # Overwriting url is safe here as request will not modify it past
        # this point.

        content_type = to_unicode(req.headers.get('Content-Type', ''))
        if self.signature_method == SIGNATURE_TYPE_BODY:
            content_type = CONTENT_TYPE_FORM_URLENCODED
        elif not content_type and extract_params(req.body):
            content_type = CONTENT_TYPE_FORM_URLENCODED

        if CONTENT_TYPE_FORM_URLENCODED in content_type:
            req.headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED
            req.url, headers, req.body = self.sign_request(req)
        elif self.force_include_body:
            # To allow custom clients to work on non form encoded bodies.
            req.url, headers, req.body = self.sign_request(req)
        else:
            # Omit body data in the signing of non form-encoded requests
            req.url, headers, _ = self.sign(
                req.method, req.url, '', req.headers)

        req.prepare_headers(headers)
        req.url = to_native_string(req.url)
        return req
