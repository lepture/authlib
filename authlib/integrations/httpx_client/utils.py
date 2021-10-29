HTTPX_CLIENT_KWARGS = [
    'headers', 'cookies', 'verify', 'cert', 'http1', 'http2',
    'proxies', 'timeout', 'follow_redirects', 'limits', 'max_redirects',
    'event_hooks', 'base_url', 'transport', 'app', 'trust_env',
]


def extract_client_kwargs(kwargs):
    client_kwargs = {}
    for k in HTTPX_CLIENT_KWARGS:
        if k in kwargs:
            client_kwargs[k] = kwargs.pop(k)
    return client_kwargs
