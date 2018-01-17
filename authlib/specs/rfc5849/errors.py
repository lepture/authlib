"""
    authlib.specs.rfc5849.errors
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""


class OAuth1Error(Exception):
    error = None
    status_code = 400
    description = ''

    def __init__(self, description=None, status_code=None,
                 uri=None):
        if description is not None:
            self.description = description

        message = '%s: %s' % (self.error, self.description)
        super(OAuth1Error, self).__init__(message)

        if status_code is not None:
            self.status_code = status_code

        self.uri = uri

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
        if self.uri:
            error.append(('error_uri', self.uri))
        return error

    def get_headers(self):
        """Get a list of headers."""
        return [
            ('Content-Type', 'application/json'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache')
        ]


class InvalidRequestError(OAuth1Error):
    error = 'invalid_request'


class InvalidSignatureError(OAuth1Error):
    error = 'invalid_signature'


class AccessDeniedError(OAuth1Error):
    error = 'access_denied'
    description = (
        'The resource owner or authorization server denied the request'
    )


class MethodNotAllowedError(OAuth1Error):
    error = 'method_not_allowed'
    status_code = 405
