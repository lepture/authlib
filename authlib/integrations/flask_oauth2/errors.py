from werkzeug.exceptions import HTTPException


class _HTTPException(HTTPException):
    def __init__(self, code, body, headers, response=None):
        super(_HTTPException, self).__init__(None, response)
        self.code = code

        self.body = body
        self.headers = headers

    def get_body(self, environ=None):
        return self.body

    def get_headers(self, environ=None):
        return self.headers


def raise_http_exception(status, body, headers):
    raise _HTTPException(status, body, headers)
