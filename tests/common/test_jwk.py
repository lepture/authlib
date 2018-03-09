import unittest
from authlib.specs.rfc7517 import JWK
from authlib.specs.rfc7518 import JWK_ALGORITHMS
from authlib.common.encoding import base64_to_int
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKey
)

jwk = JWK(algorithms=JWK_ALGORITHMS)


class JWKTest(unittest.TestCase):
    def assertBase64IntEqual(self, x, y):
        self.assertEqual(base64_to_int(x), base64_to_int(y))

    def test_ec_public_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.1
        obj = {
            "kty": "EC",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "crv": "P-521",
            "x": (
                "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
                "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
            "y": (
                "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
                "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")
        }
        key = jwk.loads(obj)
        self.assertIsInstance(key, EllipticCurvePublicKey)
        new_obj = jwk.dumps(key)
        self.assertEqual(new_obj['crv'], obj['crv'])
        self.assertBase64IntEqual(new_obj['x'], obj['x'])
        self.assertBase64IntEqual(new_obj['y'], obj['y'])

    def test_ec_private_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.2
        obj = {
            "kty": "EC",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "crv": "P-521",
            "x": (
                "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
                "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"),
            "y": (
                "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
                "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"),
            "d": (
                "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"
                "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")
        }
        key = jwk.loads(obj)
        self.assertIsInstance(key, EllipticCurvePrivateKey)
        new_obj = jwk.dumps(key, 'EC')
        self.assertEqual(new_obj['crv'], obj['crv'])
        self.assertBase64IntEqual(new_obj['x'], obj['x'])
        self.assertBase64IntEqual(new_obj['y'], obj['y'])
        self.assertBase64IntEqual(new_obj['d'], obj['d'])

    def test_rsa_public_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.3
        obj = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": ("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
                  "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
                  "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
                  "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
                  "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
                  "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
                  "HdrNP5zw"),
            "e": "AQAB"
        }
        key = jwk.loads(obj)
        self.assertIsInstance(key, RSAPublicKey)
        new_obj = jwk.dumps(key)
        self.assertBase64IntEqual(new_obj['n'], obj['n'])
        self.assertBase64IntEqual(new_obj['e'], obj['e'])

    def test_rsa_private_key(self):
        # https://tools.ietf.org/html/rfc7520#section-3.4
        obj = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": ("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
                  "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
                  "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
                  "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
                  "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
                  "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
                  "HdrNP5zw"),
            "e": "AQAB",
            "d": ("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
                  "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
                  "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
                  "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
                  "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
                  "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
                  "OpBrQzwQ"),
            "p": ("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
                  "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
                  "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
                  "bUq0k"),
            "q": ("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
                  "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
                  "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
                  "s7pFc"),
            "dp": ("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
                   "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
                   "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
                   "59ehik"),
            "dq": ("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
                   "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
                   "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
                   "T1cYF8"),
            "qi": ("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
                   "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
                   "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
                   "z8aaI4")
        }
        key = jwk.loads(obj)
        self.assertIsInstance(key, RSAPrivateKey)
        new_obj = jwk.dumps(key, 'RSA')
        self.assertBase64IntEqual(new_obj['n'], obj['n'])
        self.assertBase64IntEqual(new_obj['e'], obj['e'])
        self.assertBase64IntEqual(new_obj['d'], obj['d'])
        self.assertBase64IntEqual(new_obj['p'], obj['p'])
        self.assertBase64IntEqual(new_obj['q'], obj['q'])
        self.assertBase64IntEqual(new_obj['dp'], obj['dp'])
        self.assertBase64IntEqual(new_obj['dq'], obj['dq'])
        self.assertBase64IntEqual(new_obj['qi'], obj['qi'])

    def test_mac_computation(self):
        # https://tools.ietf.org/html/rfc7520#section-3.5
        obj = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        }
        key = jwk.loads(obj)
        new_obj = jwk.dumps(key)
        self.assertEqual(obj['k'], new_obj['k'])
