# -*- coding: utf-8 -*-
import json
from requests import Session
from authlib.common.urls import url_decode
from authlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_TYPE_HEADER,
)
from .errors import FetchTokenDeniedError
from .oauth1_protocol import OAuth1Protocol
from ..deprecate import deprecate


class OAuth1Session(OAuth1Protocol, Session):
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
    def __init__(self, client_id, client_secret=None,
                 token=None, token_secret=None,
                 redirect_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 force_include_body=False, **kwargs):
        Session.__init__(self)
        OAuth1Protocol.__init__(
            self, client_id, client_secret=client_secret,
            token=token, token_secret=token_secret,
            redirect_uri=redirect_uri, rsa_key=rsa_key, verifier=verifier,
            signature_method=signature_method, signature_type=signature_type,
            force_include_body=force_include_body, **kwargs)

    def authorization_url(self, url, request_token=None, **kwargs):  # pragma: no cover
        deprecate('Use "create_authorization_url" instead', '0.12')
        return self.create_authorization_url(url, request_token, **kwargs)

    def _fetch_token(self, url, **kwargs):
        resp = self.post(url, **kwargs)

        if resp.status_code >= 400:
            error = "Token request failed with code {}, response was '{}'."
            message = error.format(resp.status_code, resp.text)
            raise FetchTokenDeniedError(description=message)

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
        """When being redirected we should always strip Authorization
        header, since nonce may not be reused as per OAuth spec.
        """
        if 'Authorization' in prepared_request.headers:
            # If we get redirected to a new host, we should strip out
            # any authentication headers.
            prepared_request.headers.pop('Authorization', True)
            prepared_request.prepare_auth(self.auth)
