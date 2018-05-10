# -*- coding: utf-8 -*-
from requests.auth import AuthBase
from requests.utils import to_native_string
from ..common.encoding import to_native
from ..common.urls import extract_params
from ..specs.rfc5849 import Client
from ..specs.rfc5849 import SIGNATURE_TYPE_BODY


CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'


class OAuth1Auth(AuthBase, Client):
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

        content_type = to_native(req.headers.get('Content-Type', ''))
        if self.signature_type == SIGNATURE_TYPE_BODY:
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
