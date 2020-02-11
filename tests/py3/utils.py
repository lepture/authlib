import json
from httpx import Response
from httpx.dispatch.base import AsyncDispatcher


class MockDispatch(AsyncDispatcher):
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

    async def send(self, request, verify=None, cert=None, timeout=None):
        if self.assert_func:
            self.assert_func(request)

        return Response(
            self.status_code,
            content=self.body,
            headers=self.headers,
            request=request,
        )


class PathMapDispatch(AsyncDispatcher):
    def __init__(self, path_maps):
        self.path_maps = path_maps

    async def send(self, request, verify=None, cert=None, timeout=None):
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

        return Response(
            status_code,
            content=body,
            headers=headers,
            request=request,
        )
