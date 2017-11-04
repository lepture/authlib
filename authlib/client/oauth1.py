# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from requests import Session
from requests.auth import AuthBase
from requests.utils import to_native_string
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


class TokenRequestDenied(ValueError):

    def __init__(self, message, response):
        super(TokenRequestDenied, self).__init__(message)
        self.response = response

    @property
    def status_code(self):
        """For backwards-compatibility purposes"""
        return self.response.status_code


class TokenMissing(ValueError):
    def __init__(self, message, response):
        super(TokenMissing, self).__init__(message)
        self.response = response


class VerifierMissing(ValueError):
    pass


class OAuth1Session(Session):
    def __init__(self, client_key, client_secret=None,
                 resource_owner_key=None, resource_owner_secret=None,
                 callback_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 force_include_body=False):
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
            raise TokenMissing(
                'Response does not contain a token: {resp}'.format(resp=token),
                token,
            )
        if 'oauth_token_secret' in token:
            self._client.resource_owner_secret = token['oauth_token_secret']
        if 'oauth_verifier' in token:
            self._client.verifier = token['oauth_verifier']

    def authorization_url(self, url, request_token=None, **kwargs):
        kwargs['oauth_token'] = request_token or self._client.resource_owner_key
        if self._client.callback_uri:
            kwargs['oauth_callback'] = self._client.callback_uri
        return add_params_to_uri(url, kwargs.items())

    def fetch_request_token(self, url, realm=None, **kwargs):
        self._client.realm = ' '.join(realm) if realm else None
        token = self._fetch_token(url, **kwargs)
        self._client.callback_uri = None
        self._client.realm = None
        return token

    def fetch_access_token(self, url, verifier=None, **kwargs):
        if verifier:
            self._client.verifier = verifier
        if not self._client.verifier:
            raise VerifierMissing('No client verifier has been set.')
        token = self._fetch_token(url, **kwargs)
        self._client.verifier = None
        return token

    def parse_authorization_response(self, url):
        """Extract parameters from the post authorization redirect
        response URL.

        :param url: The full URL that resulted from the user being redirected
                    back from the OAuth provider to you, the client.
        :returns: A dict of parameters extracted from the URL.

        >>> redirect_response = 'https://127.0.0.1/callback?oauth_token=kjerht2309uf&oauth_verifier=w34o8967345'
        >>> oauth_session = OAuth1Session('client-key', client_secret='secret')
        >>> oauth_session.parse_authorization_response(redirect_response)
        {
            'oauth_token: 'kjerht2309u',
            'oauth_verifier: 'w34o8967345',
        }
        """
        token = dict(url_decode(urlparse.urlparse(url).query))
        self.token = token
        return token

    def _fetch_token(self, url, **kwargs):
        resp = self.post(url, **kwargs)

        if resp.status_code >= 400:
            error = "Token request failed with code {}, response was '{}'."
            raise TokenRequestDenied(
                error.format(resp.status_code, resp.text), resp)

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
