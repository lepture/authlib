import hashlib
from authlib.common.encoding import to_bytes, to_unicode, urlsafe_b64encode


def create_s256_code_challenge(code_verifier):
    """Create S256 code_challenge with the given code_verifier."""
    data = hashlib.sha256(to_bytes(code_verifier, 'ascii')).digest()
    return to_unicode(urlsafe_b64encode(data))


def compare_plain_code_challenge(code_verifier, code_challenge):
    # If the "code_challenge_method" from Section 4.3 was "plain",
    # they are compared directly
    return code_verifier == code_challenge


def compare_s256_code_challenge(code_verifier, code_challenge):
    # BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
    return create_s256_code_challenge(code_verifier) == code_challenge
