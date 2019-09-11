#: coding: utf-8
from authlib.consts import default_json_headers


class AuthlibBaseError(Exception):
    """Base Exception for all errors in Authlib."""

    #: short-string error code
    error = None
    #: long-string to describe this error
    description = ''
    #: web page that describes this error
    uri = None

    def __init__(self, error=None, description=None, uri=None):
        if error is not None:
            self.error = error
        if description is not None:
            self.description = description
        if uri is not None:
            self.uri = uri

        message = '{}: {}'.format(self.error, self.description)
        super(AuthlibBaseError, self).__init__(message)

    def __repr__(self):
        return '<{} "{}">'.format(self.__class__.__name__, self.error)


class AuthlibHTTPError(AuthlibBaseError):
    #: HTTP status code
    status_code = 400

    def __init__(self, error=None, description=None, uri=None,
                 status_code=None):
        super(AuthlibHTTPError, self).__init__(error, description, uri)
        if status_code is not None:
            self.status_code = status_code
        self._translations = None
        self._error_uris = None

    def gettext(self, s):
        if self._translations:
            return self._translations.gettext(s)
        return s

    def get_error_description(self):
        return self.description

    def get_error_uri(self):
        if self.uri:
            return self.uri
        if self._error_uris:
            return self._error_uris.get(self.error)

    def get_body(self):
        error = [('error', self.error)]

        description = self.get_error_description()
        if description:
            error.append(('error_description', description))

        uri = self.get_error_uri()
        if uri:
            error.append(('error_uri', uri))
        return error

    def get_headers(self):
        return default_json_headers

    def __call__(self, translations=None, error_uris=None):
        self._translations = translations
        self._error_uris = error_uris
        body = dict(self.get_body())
        headers = self.get_headers()
        return self.status_code, body, headers
