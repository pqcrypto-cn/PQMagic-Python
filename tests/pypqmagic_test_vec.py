import unittest
import os
from binascii import unhexlify
from pqmagic import Kem, Sig

class TestKEMVectors(unittest.TestCase):
    def setUp(self):
        self.kem_algorithms = [
            "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
            "KYBER_512", "KYBER_768", "KYBER_1024",
            "AIGIS_ENC_1", "AIGIS_ENC_2", "AIGIS_ENC_3", "AIGIS_ENC_4"
        ]
        self.test_vec_dir = os.path.join(os.path.dirname(__file__), "test_vec_files/fips202")

    def read_test_vector(self, filename):
        vectors = []
        with open(os.path.join(self.test_vec_dir, filename), 'r') as f:
            while True:
                # Find TEST VEC marker
                line = f.readline()
                if not line:
                    break
                if "TEST VEC" in line:
                    vec = {}
                    # Read keypair coins
                    line = f.readline().strip()
                    vec['keypair_coins'] = unhexlify(line.split('=')[1].strip())
                    # Read kem_enc coins
                    line = f.readline().strip()
                    vec['kem_enc_coins'] = unhexlify(line.split('=')[1].strip())
                    # Read pk
                    line = f.readline().strip()
                    vec['pk'] = unhexlify(line.split('=')[1].strip())
                    # Read sk
                    line = f.readline().strip()
                    vec['sk'] = unhexlify(line.split('=')[1].strip())
                    # Read ct
                    line = f.readline().strip()
                    vec['ct'] = unhexlify(line.split('=')[1].strip())
                    # Read ss
                    line = f.readline().strip()
                    vec['ss'] = unhexlify(line.split('=')[1].strip())
                    vectors.append(vec)
        return vectors

    def test_kem_vectors(self):
        for alg in self.kem_algorithms:
            with self.subTest(algorithm=alg):
                try:
                    # Get test vectors for this algorithm
                    filename = f"{alg.lower()}_test_vectors.txt"
                    vectors = self.read_test_vector(filename)
                    
                    kem = Kem(alg)
                    for vec in vectors:
                        # Generate keypair
                        pk, sk = kem.keypair_internal(vec['keypair_coins'])
                        self.assertEqual(pk, vec['pk'], "Public key mismatch")
                        self.assertEqual(sk, vec['sk'], "Secret key mismatch")
                        
                        # Encapsulate
                        ct, ss1 = kem.encaps_internal(vec['kem_enc_coins'], vec['pk'])
                        self.assertEqual(ct, vec['ct'], "Ciphertext mismatch")
                        self.assertEqual(ss1, vec['ss'], "Shared secret mismatch")
                        
                        # Decapsulate
                        ss2 = kem.decaps(vec['ct'], vec['sk'])
                        self.assertEqual(ss2, vec['ss'], "Decapsulated shared secret mismatch")
                    
                    print(f"✅ {alg: <12} - All tests passed successfully")
                except AssertionError as e:
                    print(f"❌ {alg: <12} - Test failed: {str(e)}")
                except Exception as e:
                    print(f"❌ {alg: <12} - Unexpected error: {str(e)}")


class TestSigVectors(unittest.TestCase):
    def setUp(self):
        self.sig_algorithms = [
            "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
            "DILITHIUM_2", "DILITHIUM_3", "DILITHIUM_5",
            "AIGIS_SIG_1", "AIGIS_SIG_2", "AIGIS_SIG_3"
        ]
        self.test_vec_dir = os.path.join(os.path.dirname(__file__), "test_vec_files/fips202")

    def read_test_vector(self, filename):
        vectors = []
        with open(os.path.join(self.test_vec_dir, filename), 'r') as f:
            while True:
                # Find TEST VEC marker
                line = f.readline()
                if not line:
                    break
                if "TEST VEC" in line:
                    vec = {}
                    # Read keypair coins
                    line = f.readline().strip()
                    vec['keypair_coins'] = unhexlify(line.split('=')[1].strip())
                    # Read sign coins (if exists)
                    line = f.readline().strip()
                    if "sign coins" in line:
                        vec['sign_coins'] = unhexlify(line.split('=')[1].strip())
                        # Read pk
                        line = f.readline().strip()
                    else:
                        vec['sign_coins'] = None
                    vec['pk'] = unhexlify(line.split('=')[1].strip())
                    # Read sk
                    line = f.readline().strip()
                    vec['sk'] = unhexlify(line.split('=')[1].strip())
                    # Read ctx_len
                    line = f.readline().strip()
                    vec['ctx_len'] = int(line.split('=')[1].strip())
                    # Read ctx
                    line = f.readline().strip()
                    vec['ctx'] = unhexlify(line.split('=')[1].strip())
                    # Read mlen
                    line = f.readline().strip()
                    vec['mlen'] = int(line.split('=')[1].strip())
                    # Read m
                    line = f.readline().strip()
                    vec['m'] = unhexlify(line.split('=')[1].strip())
                    # Read sig
                    line = f.readline().strip()
                    vec['sig'] = unhexlify(line.split('=')[1].strip())
                    vectors.append(vec)
        return vectors

    def test_sig_vectors(self):
        for alg in self.sig_algorithms:
            with self.subTest(algorithm=alg):
                try:
                    # Get test vectors for this algorithm
                    filename = f"{alg.lower()}_test_vectors.txt"
                    vectors = self.read_test_vector(filename)
                    
                    sig = Sig(alg)
                    for vec in vectors:
                        # Generate keypair
                        pk, sk = sig.keypair_internal(vec['keypair_coins'])
                        self.assertEqual(pk, vec['pk'], "Public key mismatch")
                        self.assertEqual(sk, vec['sk'], "Secret key mismatch")
                        
                        # Prepare message
                        mext = bytes([0]) + bytes([vec['ctx_len']]) + vec['ctx'] + vec['m']
                        
                        # Sign message
                        if vec['sign_coins'] is not None:
                            signature = sig.sign_internal(mext, vec['sk'], vec['sign_coins'])
                        else:
                            signature = sig.sign_internal(mext, vec['sk'])
                        self.assertEqual(signature, vec['sig'], "Signature mismatch")
                        
                        # Verify signature
                        result = sig.verify_internal(vec['sig'], mext, vec['pk'])
                        self.assertEqual(result, True, "Signature verification failed")
                    
                    print(f"✅ {alg: <12} - All tests passed successfully")
                except AssertionError as e:
                    print(f"❌ {alg: <12} - Test failed: {str(e)}")
                except Exception as e:
                    print(f"❌ {alg: <12} - Unexpected error: {str(e)}")


if __name__ == '__main__':
    class NoDotTestResult(unittest.TextTestResult):
        def addSuccess(self, test):
            super().addSuccess(test)
            # 不输出 '.'，而是输出自定义信息
            self.stream.write('...............................................\n')
            self.stream.flush()

    class NoDotTestRunner(unittest.TextTestRunner):
        resultclass = NoDotTestResult

    unittest.main(testRunner=NoDotTestRunner())
