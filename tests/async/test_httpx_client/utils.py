import json
from httpx import (
    AsyncDispatcher,
    AsyncResponse,
)


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

        return AsyncResponse(
            self.status_code,
            content=self.body,
            headers=self.headers,
            request=request,
        )
