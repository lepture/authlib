# -*- coding: utf-8 -*-
from requests import Session
from requests.auth import AuthBase
from authlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_TYPE_HEADER,
)
from authlib.common.encoding import to_native
from authlib.oauth1 import ClientAuth, ClientProtocol
from ..deprecate import deprecate


class OAuth1Auth(AuthBase, ClientAuth):
    """Signs the request using OAuth 1 (RFC5849)"""

    def __call__(self, req):
        url, headers, body = self.prepare(
            req.method, req.url, req.body, req.headers)

        req.url = to_native(url)
        req.prepare_headers(headers)
        if body:
            req.body = body
        return req


class OAuth1Session(ClientProtocol, Session):
    """Construct a new OAuth 1 client requests session.

    :param client_id: Consumer key, which you get from registration.
    :param client_secret: Consumer Secret, which you get from registration.
    :param token: A token string, also referred to as request token or access
                  token depending on when in the workflow it is used.
    :param token_secret: A token secret obtained with either a request or
                         access token. Often referred to as token secret.
    :param callback_uri: The URL the user is redirect back to after
                         authorization.
    :param rsa_key: The private RSA key as a string. Can only be used with
                    signature_method=authlib.oauth1.SIGNATURE_RSA.
    :param verifier: A verifier string to prove authorization was granted.
    :param signature_method: Signature methods for OAuth 1, available types:

                             * :data:`authlib.oauth1.SIGNATURE_HMAC_SHA1`
                             * :data:`authlib.oauth1.SIGNATURE_RSA_SHA1`
                             * :data:`authlib.oauth1.SIGNATURE_PLAINTEXT`

                             Default is ``SIGNATURE_HMAC_SHA1``. You can extend
                             signature method via ``rfc5849.Client``.
    :param signature_type: Signature type decides where the OAuth
                           parameters are added. Either in the
                           Authorization header (default) or to the URL
                           query parameters or the request body. Defined as:

                           * :data:`authlib.oauth1.SIGNATURE_TYPE_HEADER`
                           * :data:`authlib.oauth1.SIGNATURE_TYPE_BODY`
                           * :data:`authlib.oauth1.SIGNATURE_TYPE_QUERY`

    :param force_include_body: Always include the request body in the
                               signature creation.
    :param kwargs: Extra parameters to include.
    """
    auth_class = OAuth1Auth

    def __init__(self, client_id, client_secret=None,
                 token=None, token_secret=None,
                 redirect_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 force_include_body=False, **kwargs):
        Session.__init__(self)
        OAuth1Protocol.__init__(
            self, session=self,
            client_id=client_id, client_secret=client_secret,
            token=token, token_secret=token_secret,
            redirect_uri=redirect_uri, rsa_key=rsa_key, verifier=verifier,
            signature_method=signature_method, signature_type=signature_type,
            force_include_body=force_include_body, **kwargs)

    def authorization_url(self, url, request_token=None, **kwargs):  # pragma: no cover
        deprecate('Use "create_authorization_url" instead', '0.12')
        return self.create_authorization_url(url, request_token, **kwargs)

    def rebuild_auth(self, prepared_request, response):
        """When being redirected we should always strip Authorization
        header, since nonce may not be reused as per OAuth spec.
        """
        if 'Authorization' in prepared_request.headers:
            # If we get redirected to a new host, we should strip out
            # any authentication headers.
            prepared_request.headers.pop('Authorization', True)
            prepared_request.prepare_auth(self.auth)
