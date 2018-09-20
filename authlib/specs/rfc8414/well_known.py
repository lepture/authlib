from authlib.common.urls import urlparse

WELL_KNOWN_URL = '/.well-known/oauth-authorization-server'


def get_well_known_url(issuer):
    """Get well-known URI with issuer via `Section 3.1`_.

    .. _`Section 3.1`: https://tools.ietf.org/html/rfc8414#section-3.1

    :param issuer: URL of the issuer
    :return: URL
    """
    parsed = urlparse.urlparse(issuer)
    path = parsed.path
    if path and path != '/':
        return WELL_KNOWN_URL + path
    return WELL_KNOWN_URL
