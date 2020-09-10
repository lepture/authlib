import json
from starlette.requests import Request as ASGIRequest
from starlette.responses import Response as ASGIResponse
from werkzeug.wrappers import Request as WSGIRequest
from werkzeug.wrappers import Response as WSGIResponse


class AsyncMockDispatch:
    def __init__(self, body=b'', status_code=200, headers=None,
                 assert_func=None):
        if headers is None:
            headers = {}
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        else:
            if isinstance(body, str):
                body = body.encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        self.body = body
        self.status_code = status_code
        self.headers = headers
        self.assert_func = assert_func

    async def __call__(self, scope, receive, send):
        request = ASGIRequest(scope, receive=receive)

        if self.assert_func:
            await self.assert_func(request)

        response = ASGIResponse(
            status_code=self.status_code,
            content=self.body,
            headers=self.headers,
        )
        await response(scope, receive, send)


class AsyncPathMapDispatch:
    def __init__(self, path_maps):
        self.path_maps = path_maps

    async def __call__(self, scope, receive, send):
        request = ASGIRequest(scope, receive=receive)

        rv = self.path_maps[request.url.path]
        status_code = rv.get('status_code', 200)
        body = rv.get('body')
        headers = rv.get('headers', {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        else:
            if isinstance(body, str):
                body = body.encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = ASGIResponse(
            status_code=status_code,
            content=body,
            headers=headers,
        )
        await response(scope, receive, send)

class MockDispatch:
    def __init__(self, body=b'', status_code=200, headers=None,
                 assert_func=None):
        if headers is None:
            headers = {}
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        else:
            if isinstance(body, str):
                body = body.encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        self.body = body
        self.status_code = status_code
        self.headers = headers
        self.assert_func = assert_func

    def __call__(self, environ, start_response):
        request = WSGIRequest(environ)

        if self.assert_func:
            self.assert_func(request)

        response = WSGIResponse(
            status=self.status_code,
            response=self.body,
            headers=self.headers,
        )
        return response(environ, start_response)


class PathMapDispatch:
    def __init__(self, path_maps):
        self.path_maps = path_maps

    def __call__(self, environ, start_response):
        request = WSGIRequest(environ)

        rv = self.path_maps[request.url.path]
        status_code = rv.get('status_code', 200)
        body = rv.get('body', b'')
        headers = rv.get('headers', {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        else:
            if isinstance(body, str):
                body = body.encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = WSGIResponse(
            status=status_code,
            response=body,
            headers=headers,
        )
        return response(environ, start_response)
