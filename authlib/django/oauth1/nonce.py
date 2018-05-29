from django.core.cache import cache


def exists_nonce_in_cache(nonce, request, timeout):
    key_prefix = 'nonce:'
    timestamp = request.timestamp
    client_id = request.client_id
    token = request.token
    key = '{}{}-{}-{}'.format(key_prefix, nonce, timestamp, client_id)
    if token:
        key = '{}-{}'.format(key, token)

    rv = bool(cache.get(key))
    cache.set(key, 1, timeout=timeout)
    return rv
