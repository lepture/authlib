"""
    authlib.specs.rfc5849.errors
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    RFC5849 has no definition on errors. This module is designed by
    Authlib based on OAuth 1.0a `Section 10`_ with some changes.

    .. _`Section 10`: https://oauth.net/core/1.0a/#rfc.section.10
"""
from authlib.common.security import is_secure_transport


class OAuth1Error(Exception):
    error = None
    status_code = 400
    description = ''

    def __init__(self, description=None, status_code=None):
        if description is not None:
            self.description = description

        message = '%s: %s' % (self.error, self.description)
        super(OAuth1Error, self).__init__(message)

        if status_code is not None:
            self.status_code = status_code

    def __str__(self):
        return '{} {}: {}'.format(
            self.status_code,
            self.error,
            self.description
        )

    def __repr__(self):
        return "<{} '{}: {}'>".format(
            self.__class__.__name__,
            self.status_code,
            self.error
        )

    def get_body(self):
        """Get a list of body."""
        error = [('error', self.error)]
        if self.description:
            error.append(('error_description', self.description))
        return error

    def get_headers(self):
        """Get a list of headers."""
        return [
            ('Content-Type', 'application/x-www-form-urlencoded'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache')
        ]


class InsecureTransportError(OAuth1Error):
    error = 'insecure_transport'
    description = 'OAuth 2 MUST utilize https.'

    @classmethod
    def check(cls, uri):
        if not is_secure_transport(uri):
            raise cls()


class InvalidRequestError(OAuth1Error):
    error = 'invalid_request'


class UnsupportedParameterError(OAuth1Error):
    error = 'unsupported_parameter'


class UnsupportedSignatureMethodError(OAuth1Error):
    error = 'unsupported_signature_method'


class MissingRequiredParameterError(OAuth1Error):
    error = 'missing_required_parameter'

    def __init__(self, key):
        description = 'missing "{}" in parameters'.format(key)
        super(MissingRequiredParameterError, self).__init__(description)


class DuplicatedOAuthProtocolParameterError(OAuth1Error):
    error = 'duplicated_oauth_protocol_parameter'


class InvalidClientError(OAuth1Error):
    error = 'invalid_client'
    status_code = 401


class InvalidTokenError(OAuth1Error):
    error = 'invalid_token'
    description = 'Invalid or expired "oauth_token" in parameters'
    status_code = 401


class InvalidSignatureError(OAuth1Error):
    error = 'invalid_signature'
    status_code = 401


class InvalidNonceError(OAuth1Error):
    error = 'invalid_nonce'
    status_code = 401


class AccessDeniedError(OAuth1Error):
    error = 'access_denied'
    description = (
        'The resource owner or authorization server denied the request'
    )


class MethodNotAllowedError(OAuth1Error):
    error = 'method_not_allowed'
    status_code = 405
