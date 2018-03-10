from authlib.common.urls import add_params_to_qs


def prepare_token_introspection_request(
        token, optional=None, body=None, headers=None):
    """Construct request body and headers for revocation endpoint.

    :param token: access_token or refresh_token string.
    :param optional: Optional, token query parameters.
    :param body: current request body.
    :param headers: current request headers.
    :returns: (body, headers)

    https://tools.ietf.org/html/rfc7662#section-2.1
    """
    params = [('token', token)]

    if optional is None:
        optional = {}

    for k, v in optional.items():
        params.append((k, v))

    body = add_params_to_qs(body or '', params)

    if headers is None:
        headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return body, headers
