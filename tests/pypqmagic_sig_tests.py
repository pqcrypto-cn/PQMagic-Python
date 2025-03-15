import unittest
from pqmagic import SIG, PQMAGIC_SUCCESS, PQMAGIC_FAILURE

class TestSIG(unittest.TestCase):
    def setUp(self):
        # signature algorithms without context parameter
        self.sig_algorithms1 = [
            "SLH_DSA_SHA2_128f", "SLH_DSA_SHA2_128s",
            "SLH_DSA_SHA2_192f", "SLH_DSA_SHA2_192s",
            "SLH_DSA_SHA2_256f", "SLH_DSA_SHA2_256s",
            "SLH_DSA_SHAKE_128f", "SLH_DSA_SHAKE_128s",
            "SLH_DSA_SHAKE_192f", "SLH_DSA_SHAKE_192s",
            "SLH_DSA_SHAKE_256f", "SLH_DSA_SHAKE_256s",
            "SLH_DSA_SM3_128f", "SLH_DSA_SM3_128s",
            "DILITHIUM_2", "DILITHIUM_3", "DILITHIUM_5",
            "SPHINCS_Alpha_SHA2_128f", "SPHINCS_Alpha_SHA2_128s",
            "SPHINCS_Alpha_SHA2_192f", "SPHINCS_Alpha_SHA2_192s",
            "SPHINCS_Alpha_SHA2_256f", "SPHINCS_Alpha_SHA2_256s",
            "SPHINCS_Alpha_SHAKE_128f", "SPHINCS_Alpha_SHAKE_128s",
            "SPHINCS_Alpha_SHAKE_192f", "SPHINCS_Alpha_SHAKE_192s",
            "SPHINCS_Alpha_SHAKE_256f", "SPHINCS_Alpha_SHAKE_256s",
            "SPHINCS_Alpha_SM3_128f", "SPHINCS_Alpha_SM3_128s"
        ]

        # signature algorithms with context parameter
        self.sig_algorithms2 = [
            "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
            "AIGIS_SIG_1", "AIGIS_SIG_2", "AIGIS_SIG_3"
        ]

        self.message = b'59B3A24B5EF1D1C05552CF2819D42D61565764CA4A588AE5107B50957EFA0813A1822385B2FCF726ED336EB33DD211C774C824C45B83B7220971DB'
        self.context = b'F99081AF71'

    def test_sign_verify(self):
        for alg in self.sig_algorithms1:
            with self.subTest(algorithm = alg):
                sig = SIG(alg)
                pk, sk = sig.keypair()
                signature = sig.sign(self.message, sk)
                result = sig.verify(signature, self.message, pk)
                self.assertEqual(result, PQMAGIC_SUCCESS)
        for alg in self.sig_algorithms2:
            with self.subTest(algorithm = alg):
                sig = SIG(alg)
                pk, sk = sig.keypair()
                signature = sig.sign(self.message, self.context, sk)
                result = sig.verify(signature, self.message, self.context, pk)
                self.assertEqual(result, PQMAGIC_SUCCESS)

    def test_sign_pack_open(self):
        for alg in self.sig_algorithms1:
            with self.subTest(algorithm = alg):
                sig = SIG(alg)
                pk, sk = sig.keypair()
                signed_message = sig.sign_pack(self.message, sk)
                result = sig.open(self.message, signed_message, pk)
                self.assertEqual(result, PQMAGIC_SUCCESS)
        for alg in self.sig_algorithms2:
            with self.subTest(algorithm = alg):
                sig = SIG(alg)
                pk, sk = sig.keypair()
                signed_message = sig.sign_pack(self.message, self.context, sk)
                result = sig.open(self.message, signed_message, self.context, pk)
                self.assertEqual(result, PQMAGIC_SUCCESS)



if __name__ == '__main__':
    unittest.main()