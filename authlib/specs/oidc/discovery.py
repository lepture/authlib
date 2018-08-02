import logging

import requests

log = logging.getLogger(__name__)

# required keys of an OIDC configuration JSON
REQUIRED = ('issuer', 'authorization_endpoint', 'jwks_uri',
            'response_types_supported', 'subject_types_supported',
            'id_token_signing_alg_values_supported')


def get_oid_provider_meta(oid_discovery_url):
    """Gather OpenID Connect Configuration.

    This method gathers the OIDC configuration and checks for the
    required keys as defined in:
    https://openid.net/specs/openid-connect-discovery-1_0.htm://openid.net/specs/openid-connect-discovery-1_0.html

    :param oid_discovery_url: OpenID Connect disovery url. If it does
                              not end with
                              /.well-known/openid-configuration, it is
                              automatically appended.
    :return: dict
    """
    if not oid_discovery_url.endswith('/.well-known/openid-configuration'):
        oid_discovery_url += '/.well-known/openid-configuration'

    resp = requests.get(oid_discovery_url)
    conf = resp.json()

    # go through list of required values and throw an error if absent
    for key in REQUIRED:
        if key not in conf:
            raise ValueError('{} is missing, but a required value.'.format(key))
    return conf
