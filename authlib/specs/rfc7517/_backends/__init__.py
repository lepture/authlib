try:
    from ._cryptography import EC_TYPES, RSA_TYPES
except ImportError:
    EC_TYPES = []
    RSA_TYPES = []
