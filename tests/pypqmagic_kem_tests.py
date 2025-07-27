import unittest
from binascii import hexlify
from pqmagic import Kem

class TestKEM(unittest.TestCase):
    def setUp(self):
        self.kem_algorithms = [
            "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
            "KYBER_512", "KYBER_768", "KYBER_1024",
            "AIGIS_ENC_1", "AIGIS_ENC_2", "AIGIS_ENC_3", "AIGIS_ENC_4"
        ]

    def test_encaps_decaps(self):
        for alg in self.kem_algorithms:
            with self.subTest(algorithm = alg):
                kem = Kem(alg)
                pk, sk = kem.keypair()
                #print('pk:', hexlify(pk))
                #print('sk:', hexlify(sk))
                ciphertext, shared_secret1 = kem.encaps()
                #print('ciphertext:', hexlify(ciphertext))
                shared_secret2 = kem.decaps(ciphertext)
                #print('shared_secret:', hexlify(shared_secret))
                self.assertEqual(shared_secret1, shared_secret2)


if __name__ == '__main__':
    unittest.main()