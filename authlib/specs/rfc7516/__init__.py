"""
    authlib.specs.rfc7516
    ~~~~~~~~~~~~~~~~~~~~~

    This module represents a direct implementation of
    JSON Web Encryption (JWE).

    https://tools.ietf.org/html/rfc7516
"""

from .jwe import JWE
from .models import JWEAlgorithm, JWEEncAlgorithm, JWEZipAlgorithm
from .errors import *
