import json
from httpx import ASGIDispatch, Request


async def read_request(scope, receive):
    body = bytearray()
    while True:
        req = await receive()
        assert req["type"] == "http.request"
        assert "body" in req
        assert "more_body" in req
        body.extend(req["body"])
        if not req["more_body"]:
            break
    return Request(
        method=scope["method"],
        url="{}://{}{}".format(scope["scheme"], scope["server"], scope["path"]),
        params=str(scope["query_string"]),
        headers=scope["headers"],
        data=bytes(body),
    )


def mock_dispatch(body=b'', status_code=200, headers=None, assert_func=None):
    if headers is None:
        headers = {}
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    else:
        if isinstance(body, str):
            body = body.encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

    async def asgiapp(scope, receive, send):
        request = await read_request(scope, receive)
        if assert_func:
            await assert_func(request)
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": headers.items(),
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })

    return ASGIDispatch(asgiapp)


def path_map_dispatch(path_maps, assert_func=None):
    async def asgiapp(scope, receive, send):
        request = await read_request(scope, receive)
        if assert_func:
            await assert_func(request)

        path = scope["path"]

        rv = path_maps[path]
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

        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": headers.items(),
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })

    return ASGIDispatch(asgiapp)
