# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from requests import Session
from requests.auth import AuthBase
from requests.utils import to_native_string
from ..common.encoding import to_unicode
from ..common.urls import url_decode, extract_params
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

    def authorization_url(self, url, request_token=None, **kwargs):
        pass

    def fetch_request_token(self, url, realm=None, **kwargs):
        """Fetch a request token.

        This is the first step in the OAuth 1 workflow. A request token is
        obtained by making a signed post request to url. The token is then
        parsed from the application/x-www-form-urlencoded response and ready
        to be used to construct an authorization url.

        :param url: The request token endpoint URL.
        :param realm: A list of realms to request access to.
        :param kwargs: Optional arguments passed to "post"

        Note that a previously set callback_uri will be reset for your
        convenience, or else signature creation will be incorrect on
        consecutive requests.

        >>> request_token_url = 'https://api.twitter.com/oauth/request_token'
        >>> oauth_session = OAuth1Session('client-key', client_secret='secret')
        >>> oauth_session.fetch_request_token(request_token_url)
        {
            'oauth_token': 'sdf0o9823sjdfsdf',
            'oauth_token_secret': '2kjshdfp92i34asdasd',
        }
        """
        self._client.realm = ' '.join(realm) if realm else None
        token = self._fetch_token(url, **kwargs)
        self._client.callback_uri = None
        self._client.realm = None
        return token

    def fetch_access_token(self, url, verifier=None, **kwargs):
        pass

    def parse_authorization_response(self, url):
        pass

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
                token = url_decode(text)
        except (TypeError, ValueError) as e:
            error = ("Unable to decode token from token response. "
                     "This is commonly caused by an unsuccessful request where"
                     " a non urlencoded error message is returned. "
                     "The decoding error was %s""" % e)
            raise ValueError(error)

        self._populate_attributes(token)
        return token

    def _populate_attributes(self, token):
        if 'oauth_token' in token:
            self.resource_owner_key = token['oauth_token']
        else:
            raise TokenMissing(
                'Response does not contain a token: {resp}'.format(resp=token),
                token,
            )
        if 'oauth_token_secret' in token:
            self.resource_owner_secret = token['oauth_token_secret']
        if 'oauth_verifier' in token:
            self.verifier = token['oauth_verifier']


class OAuth1(AuthBase, Client):
    """Signs the request using OAuth 1 (RFC5849)"""

    def sign_request(self, req):
        return self.sign(req.method, req.url, req.data, req.headers)

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
            req.url, headers, _ = self.sign_request(req)

        req.prepare_headers(headers)
        req.url = to_native_string(req.url)
        return req
