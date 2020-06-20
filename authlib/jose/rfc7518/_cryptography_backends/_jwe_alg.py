import os
import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap
)
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from authlib.common.encoding import (
    to_bytes, to_native,
    urlsafe_b64decode,
    urlsafe_b64encode
)
from authlib.jose.rfc7516 import JWEAlgorithm
from ._keys import RSAKey, ECKey
from ..oct_key import OctKey


class RSAAlgorithm(JWEAlgorithm):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

    def __init__(self, name, description, pad_fn):
        self.name = name
        self.description = description
        self.padding = pad_fn

    def prepare_key(self, raw_data):
        return RSAKey.import_key(raw_data)

    def wrap(self, enc_alg, headers, key):
        cek = enc_alg.generate_cek()
        op_key = key.get_op_key('wrapKey')
        if op_key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        ek = op_key.encrypt(cek, self.padding)
        return {'ek': ek, 'cek': cek}

    def unwrap(self, enc_alg, ek, headers, key):
        # it will raise ValueError if failed
        op_key = key.get_op_key('unwrapKey')
        cek = op_key.decrypt(ek, self.padding)
        print(cek, enc_alg.key_size)
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class AESAlgorithm(JWEAlgorithm):
    def __init__(self, key_size):
        self.name = 'A{}KW'.format(key_size)
        self.description = 'AES Key Wrap using {}-bit key'.format(key_size)
        self.key_size = key_size

    def prepare_key(self, raw_data):
        return OctKey.import_key(raw_data)

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc_alg, headers, key):
        cek = enc_alg.generate_cek()
        op_key = key.get_op_key('wrapKey')
        self._check_key(op_key)
        ek = aes_key_wrap(op_key, cek, default_backend())
        return {'ek': ek, 'cek': cek}

    def unwrap(self, enc_alg, ek, headers, key):
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)
        cek = aes_key_unwrap(op_key, ek, default_backend())
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class AESGCMAlgorithm(JWEAlgorithm):
    EXTRA_HEADERS = frozenset(['iv', 'tag'])

    def __init__(self, key_size):
        self.name = 'A{}GCMKW'.format(key_size)
        self.description = 'Key wrapping with AES GCM using {}-bit key'.format(key_size)
        self.key_size = key_size

    def prepare_key(self, raw_data):
        return OctKey.import_key(raw_data)

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc_alg, headers, key):
        cek = enc_alg.generate_cek()
        op_key = key.get_op_key('wrapKey')
        self._check_key(op_key)

        #: https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        #: The "iv" (initialization vector) Header Parameter value is the
        #: base64url-encoded representation of the 96-bit IV value
        iv_size = 96
        iv = os.urandom(iv_size // 8)

        cipher = Cipher(AES(op_key), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        ek = enc.update(cek) + enc.finalize()

        h = {
            'iv': to_native(urlsafe_b64encode(iv)),
            'tag': to_native(urlsafe_b64encode(enc.tag))
        }
        return {'ek': ek, 'cek': cek, 'header': h}

    def unwrap(self, enc_alg, ek, headers, key):
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)

        iv = headers.get('iv')
        if not iv:
            raise ValueError('Missing "iv" in headers')

        tag = headers.get('tag')
        if not tag:
            raise ValueError('Missing "tag" in headers')

        iv = urlsafe_b64decode(to_bytes(iv))
        tag = urlsafe_b64decode(to_bytes(tag))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        cek = d.update(ek) + d.finalize()
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class ECDHAlgorithm(JWEAlgorithm):
    EXTRA_HEADERS = ['epk', 'apu', 'apv']
    ALLOWED_KEY_CLS = ECKey

    # https://tools.ietf.org/html/rfc7518#section-4.6
    def __init__(self, key_size=None):
        if key_size is None:
            self.name = 'ECDH-ES'
            self.description = 'ECDH-ES in the Direct Key Agreement mode'
        else:
            self.name = 'ECDH-ES+A{}KW'.format(key_size)
            self.description = (
                'ECDH-ES using Concat KDF and CEK wrapped '
                'with A{}KW').format(key_size)
        self.key_size = key_size
        self.aeskw = AESAlgorithm(key_size)

    def prepare_key(self, raw_data):
        if isinstance(raw_data, self.ALLOWED_KEY_CLS):
            return raw_data
        return ECKey.import_key(raw_data)

    def deliver(self, key, pubkey, headers, bit_size):
        # AlgorithmID
        if self.key_size is None:
            alg_id = _u32be_len_input(headers['enc'])
        else:
            alg_id = _u32be_len_input(headers['alg'])

        # PartyUInfo
        apu_info = _u32be_len_input(headers.get('apu'), True)

        # PartyVInfo
        apv_info = _u32be_len_input(headers.get('apv'), True)

        # SuppPubInfo
        pub_info = struct.pack('>I', bit_size)

        other_info = alg_id + apu_info + apv_info + pub_info
        shared_key = key.exchange_shared_key(pubkey)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=bit_size // 8,
            otherinfo=other_info,
            backend=default_backend()
        )
        return ckdf.derive(shared_key)

    def wrap(self, enc_alg, headers, key):
        if self.key_size is None:
            bit_size = enc_alg.key_size
        else:
            bit_size = self.key_size

        epk = key.generate_key(key['crv'], is_private=True)
        public_key = key.get_op_key('wrapKey')
        dk = self.deliver(epk, public_key, headers, bit_size)

        # REQUIRED_JSON_FIELDS contains only public fields
        pub_epk = {k: epk[k] for k in epk.REQUIRED_JSON_FIELDS}
        pub_epk['kty'] = epk.kty
        h = {'epk': pub_epk}
        if self.key_size is None:
            return {'ek': b'', 'cek': dk, 'header': h}

        kek = self.aeskw.prepare_key(dk)
        rv = self.aeskw.wrap(enc_alg, headers, kek)
        rv['header'] = h
        return rv

    def unwrap(self, enc_alg, ek, headers, key):
        if 'epk' not in headers:
            raise ValueError('Missing "epk" in headers')

        if self.key_size is None:
            bit_size = enc_alg.key_size
        else:
            bit_size = self.key_size

        epk = key.import_key(headers['epk'])
        public_key = epk.get_op_key('wrapKey')
        dk = self.deliver(key, public_key, headers, bit_size)

        if self.key_size is None:
            return dk

        kek = self.aeskw.prepare_key(dk)
        return self.aeskw.unwrap(enc_alg, ek, headers, kek)


def _u32be_len_input(s, base64=False):
    if not s:
        return b'\x00\x00\x00\x00'
    if base64:
        s = urlsafe_b64decode(to_bytes(s))
    else:
        s = to_bytes(s)
    return struct.pack('>I', len(s)) + s


JWE_ALG_ALGORITHMS = [
    RSAAlgorithm('RSA1_5', 'RSAES-PKCS1-v1_5', padding.PKCS1v15()),
    RSAAlgorithm(
        'RSA-OAEP', 'RSAES OAEP using default parameters',
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
    RSAAlgorithm(
        'RSA-OAEP-256', 'RSAES OAEP using SHA-256 and MGF1 with SHA-256',
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)),

    AESAlgorithm(128),  # A128KW
    AESAlgorithm(192),  # A192KW
    AESAlgorithm(256),  # A256KW
    AESGCMAlgorithm(128),  # A128GCMKW
    AESGCMAlgorithm(192),  # A192GCMKW
    AESGCMAlgorithm(256),  # A256GCMKW
    ECDHAlgorithm(None),  # ECDH-ES
    ECDHAlgorithm(128),  # ECDH-ES+A128KW
    ECDHAlgorithm(192),  # ECDH-ES+A192KW
    ECDHAlgorithm(256),  # ECDH-ES+A256KW
]

# 'PBES2-HS256+A128KW': '',
# 'PBES2-HS384+A192KW': '',
# 'PBES2-HS512+A256KW': '',
