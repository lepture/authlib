from httpx import URL
from httpx.content_streams import ByteStream
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


def rebuild_request(request, url, headers, body):
    request.url = URL(url)
    request.headers.update(headers)
    if body:
        body = to_bytes(body)
        if body != request.content:
            request._content = body
            request.stream = ByteStream(body)
    return request
