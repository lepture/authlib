import typing

from httpx import URL, Request
from authlib.common.encoding import to_bytes


HTTPX_CLIENT_KWARGS = [
    'headers', 'cookies', 'verify', 'cert', 'http_versions',
    'proxies', 'timeout', 'pool_limits', 'max_redirects',
    'base_url', 'dispatch', 'app', 'backend', 'trust_env',
    'json',
]


def extract_client_kwargs(kwargs):
    client_kwargs = {}
    for k in HTTPX_CLIENT_KWARGS:
        if k in kwargs:
            client_kwargs[k] = kwargs.pop(k)
    return client_kwargs


def rebuild_request(request: Request, url: typing.Union[str, URL],
                    headers: typing.Mapping[typing.AnyStr, typing.AnyStr], body: typing.AnyStr):
    new_request = Request(
        method=request.method,
        url=URL(url),
        headers=request.headers,
        data=to_bytes(body) if body is not None else None,
        stream=request.stream if body is None else None,
    )
    new_request.headers.update(headers)
    return new_request
