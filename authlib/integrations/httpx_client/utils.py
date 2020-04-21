from httpx import Request, URL
from httpx import RequestNotRead
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


def rebuild_request(
    old_request: Request, url=None, headers=None, body=None
) -> Request:
    new_url = URL(url or old_request.url)
    new_headers = old_request.headers
    if headers is not None:
        new_headers.update(headers)

    new_data = None
    new_stream = None

    data = to_bytes(body)
    # Only overwrite the only body if the new body is truthy
    if data:
        new_data = data
    else:
        new_stream = old_request.stream

    new_request = Request(
        old_request.method,
        new_url,
        # Params should be encoded in the new URL
        headers=new_headers,
        # Cookies are copied with the old headers
        data=new_data,
        # We ignore Files and JSON, as httpx encodes them as a stream
        stream=new_stream,
    )

    # Lazily read new request
    try:
        old_request.content
    except RequestNotRead:
        pass
    else:
        new_request.read()

    # Carry-over timer
    new_request.timer = old_request.timer

    return new_request
