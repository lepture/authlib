import time
import base64
import hashlib
from authlib.common.encoding import to_unicode, to_bytes
from authlib.common.security import generate_token
from authlib.common.urls import url_encode, extract_params
from .signature import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_TYPE_HEADER,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_QUERY,
)
from .signature import base_string_from_request
from .signature import (
    sign_rsa_sha1,
    sign_hmac_sha1,
    sign_plaintext
)
from .parameters import (
    prepare_form_encoded_body,
    prepare_headers,
    prepare_request_uri_query,
)


CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'


class Client(object):
    SIGNATURE_METHODS = {
        SIGNATURE_HMAC_SHA1: client_sign_hmac_sha1,
        SIGNATURE_RSA_SHA1: client_sign_rsa_sha1,
        SIGNATURE_PLAINTEXT: client_sign_plaintext,
    }

    @classmethod
    def register_signature_method(cls, name, sign):
        cls.SIGNATURE_METHODS[name] = sign

    def __init__(self, client_key, client_secret=None,
                 resource_owner_key=None, resource_owner_secret=None,
                 callback_uri=None, rsa_key=None, verifier=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_HEADER,
                 realm=None, force_include_body=False):
        self.client_key = client_key
        self.client_secret = client_secret
        self.resource_owner_key = resource_owner_key
        self.resource_owner_secret = resource_owner_secret
        self.callback_uri = callback_uri
        self.signature_method = signature_method
        self.signature_type = signature_type
        self.rsa_key = rsa_key
        self.verifier = verifier
        self.realm = realm
        self.force_include_body = force_include_body

    def get_oauth_signature(self, method, uri, body, headers):
        """Get an OAuth signature to be used in signing a request

        To satisfy `section 3.4.1.2`_ item 2, if the request argument's
        headers dict attribute contains a Host item, its value will
        replace any netloc part of the request argument's uri attribute
        value.

        .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2
        """
        sign = self.SIGNATURE_METHODS.get(self.signature_method)
        if not sign:
            raise ValueError('Invalid signature method.')
        return sign(self, method, uri, body, headers)

    def get_oauth_params(self, method, uri, body, headers, nonce, timestamp):
        oauth_params = [
            ('oauth_nonce', nonce),
            ('oauth_timestamp', timestamp),
            ('oauth_version', '1.0'),
            ('oauth_signature_method', self.signature_method),
            ('oauth_consumer_key', self.client_key),
        ]
        if self.resource_owner_key:
            oauth_params.append(('oauth_token', self.resource_owner_key))
        if self.callback_uri:
            oauth_params.append(('oauth_callback', self.callback_uri))
        if self.verifier:
            oauth_params.append(('oauth_verifier', self.verifier))

        # https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html
        content_type = headers.get('Content-Type', '')
        if not content_type.startswith(CONTENT_TYPE_FORM_URLENCODED):
            sig = base64.b64encode(hashlib.sha1(to_bytes(body)).digest())
            oauth_params.append(('oauth_body_hash', to_unicode(sig)))

        method = to_unicode(method)
        uri = to_unicode(uri)
        sig = self.get_oauth_signature(uri, method, body, headers)
        oauth_params.append(('oauth_signature', sig))
        return oauth_params

    def sign(self, method, uri, body, headers, nonce=None, timestamp=None):
        if nonce is None:
            nonce = generate_token()
        if timestamp is None:
            timestamp = int(time.time())

        oauth_params = self.get_oauth_params(
            method, uri, body, headers, nonce, timestamp)

        if self.signature_type == SIGNATURE_TYPE_HEADER:
            headers = prepare_headers(oauth_params, headers, realm=self.realm)

        elif self.signature_type == SIGNATURE_TYPE_BODY:
            decoded_body = extract_params(body)
            if decoded_body:
                body = prepare_form_encoded_body(oauth_params, decoded_body)
                body = url_encode(body)
                headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED

        elif self.signature_type == SIGNATURE_TYPE_QUERY:
            uri = prepare_request_uri_query(oauth_params, uri)
        else:
            raise ValueError('Unknown signature type specified.')

        return uri, headers, body


def client_sign_hmac_sha1(client, method, uri, body, headers):
    base_string = base_string_from_request(method, uri, body, headers)
    return sign_hmac_sha1(
        base_string, client.client_secret, client.resource_owner_secret
    )


def client_sign_rsa_sha1(client, method, uri, body, headers):
    base_string = base_string_from_request(method, uri, body, headers)
    return sign_rsa_sha1(base_string, client.rsa_key)


def client_sign_plaintext(client, *args, **kwargs):
    return sign_plaintext(client.client_secret, client.resource_owner_secret)
