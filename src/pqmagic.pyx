# pqmagic.pyx

cimport pqmagic
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
from libc.stdint cimport uint8_t
from libc.stddef cimport size_t

cdef enum sig_label:
    ML_DSA_44
    ML_DSA_65
    ML_DSA_87
    SLH_DSA_SHA2_128f
    SLH_DSA_SHA2_128s
    SLH_DSA_SHA2_192f
    SLH_DSA_SHA2_192s
    SLH_DSA_SHA2_256f
    SLH_DSA_SHA2_256s
    SLH_DSA_SHAKE_128f
    SLH_DSA_SHAKE_128s
    SLH_DSA_SHAKE_192f
    SLH_DSA_SHAKE_192s
    SLH_DSA_SHAKE_256f
    SLH_DSA_SHAKE_256s
    SLH_DSA_SM3_128f
    SLH_DSA_SM3_128s
    AIGIS_SIG_1
    AIGIS_SIG_2
    AIGIS_SIG_3
    DILITHIUM_2
    DILITHIUM_3
    DILITHIUM_5
    SPHINCS_Alpha_SHA2_128f
    SPHINCS_Alpha_SHA2_128s
    SPHINCS_Alpha_SHA2_192f
    SPHINCS_Alpha_SHA2_192s
    SPHINCS_Alpha_SHA2_256f
    SPHINCS_Alpha_SHA2_256s
    SPHINCS_Alpha_SHAKE_128f
    SPHINCS_Alpha_SHAKE_128s
    SPHINCS_Alpha_SHAKE_192f
    SPHINCS_Alpha_SHAKE_192s
    SPHINCS_Alpha_SHAKE_256f
    SPHINCS_Alpha_SHAKE_256s
    SPHINCS_Alpha_SM3_128f
    SPHINCS_Alpha_SM3_128s

cdef dict sig_label_map = {  
    "ML_DSA_44": ML_DSA_44,  
    "ML_DSA_65": ML_DSA_65,  
    "ML_DSA_87": ML_DSA_87,  
    "SLH_DSA_SHA2_128f": SLH_DSA_SHA2_128f,  
    "SLH_DSA_SHA2_128s": SLH_DSA_SHA2_128s,  
    "SLH_DSA_SHA2_192f": SLH_DSA_SHA2_192f,  
    "SLH_DSA_SHA2_192s": SLH_DSA_SHA2_192s,  
    "SLH_DSA_SHA2_256f": SLH_DSA_SHA2_256f,  
    "SLH_DSA_SHA2_256s": SLH_DSA_SHA2_256s,  
    "SLH_DSA_SHAKE_128f": SLH_DSA_SHAKE_128f,  
    "SLH_DSA_SHAKE_128s": SLH_DSA_SHAKE_128s,  
    "SLH_DSA_SHAKE_192f": SLH_DSA_SHAKE_192f,  
    "SLH_DSA_SHAKE_192s": SLH_DSA_SHAKE_192s,  
    "SLH_DSA_SHAKE_256f": SLH_DSA_SHAKE_256f,  
    "SLH_DSA_SHAKE_256s": SLH_DSA_SHAKE_256s,  
    "SLH_DSA_SM3_128f": SLH_DSA_SM3_128f,  
    "SLH_DSA_SM3_128s": SLH_DSA_SM3_128s,  
    "AIGIS_SIG_1": AIGIS_SIG_1,  
    "AIGIS_SIG_2": AIGIS_SIG_2,  
    "AIGIS_SIG_3": AIGIS_SIG_3,  
    "DILITHIUM_2": DILITHIUM_2,  
    "DILITHIUM_3": DILITHIUM_3,  
    "DILITHIUM_5": DILITHIUM_5,  
    "SPHINCS_Alpha_SHA2_128f": SPHINCS_Alpha_SHA2_128f,  
    "SPHINCS_Alpha_SHA2_128s": SPHINCS_Alpha_SHA2_128s,  
    "SPHINCS_Alpha_SHA2_192f": SPHINCS_Alpha_SHA2_192f,  
    "SPHINCS_Alpha_SHA2_192s": SPHINCS_Alpha_SHA2_192s,  
    "SPHINCS_Alpha_SHA2_256f": SPHINCS_Alpha_SHA2_256f,  
    "SPHINCS_Alpha_SHA2_256s": SPHINCS_Alpha_SHA2_256s,  
    "SPHINCS_Alpha_SHAKE_128f": SPHINCS_Alpha_SHAKE_128f,  
    "SPHINCS_Alpha_SHAKE_128s": SPHINCS_Alpha_SHAKE_128s,  
    "SPHINCS_Alpha_SHAKE_192f": SPHINCS_Alpha_SHAKE_192f,  
    "SPHINCS_Alpha_SHAKE_192s": SPHINCS_Alpha_SHAKE_192s,  
    "SPHINCS_Alpha_SHAKE_256f": SPHINCS_Alpha_SHAKE_256f,  
    "SPHINCS_Alpha_SHAKE_256s": SPHINCS_Alpha_SHAKE_256s,  
    "SPHINCS_Alpha_SM3_128f": SPHINCS_Alpha_SM3_128f,  
    "SPHINCS_Alpha_SM3_128s": SPHINCS_Alpha_SM3_128s,  
}  

cdef enum kem_label:
   ML_KEM_512
   ML_KEM_768
   ML_KEM_1024
   KYBER_512
   KYBER_768
   KYBER_1024
   AIGIS_ENC_1
   AIGIS_ENC_2
   AIGIS_ENC_3
   AIGIS_ENC_4

cdef dict kem_label_map = {  
    "ML_KEM_512": ML_KEM_512,  
    "ML_KEM_768": ML_KEM_768,  
    "ML_KEM_1024": ML_KEM_1024,  
    "KYBER_512": KYBER_512,  
    "KYBER_768": KYBER_768,  
    "KYBER_1024": KYBER_1024,  
    "AIGIS_ENC_1": AIGIS_ENC_1,  
    "AIGIS_ENC_2": AIGIS_ENC_2,  
    "AIGIS_ENC_3": AIGIS_ENC_3,  
    "AIGIS_ENC_4": AIGIS_ENC_4,  
}

# export constants
PQMAGIC_SUCCESS = 0
PQMAGIC_FAILURE = -1


cdef class SIG:
    cdef public sig_label label
    cdef unsigned char *pk
    cdef unsigned char *sk
    cdef public size_t public_key_size
    cdef public size_t secret_key_size
    cdef public size_t signature_size
    
    def __cinit__(self, str name):
        if name not in sig_label_map:  
            raise ValueError("Invalid algorithm name.")  
        self.label = sig_label_map[name]
     
        if(self.label == ML_DSA_44):
            self.public_key_size = pqmagic.ML_DSA_44_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_DSA_44_SECRETKEYBYTES
            self.signature_size = pqmagic.ML_DSA_44_SIGBYTES
        elif(self.label == ML_DSA_65):
            self.public_key_size = pqmagic.ML_DSA_65_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_DSA_65_SECRETKEYBYTES
            self.signature_size = pqmagic.ML_DSA_65_SIGBYTES
        elif(self.label == ML_DSA_87):
            self.public_key_size = pqmagic.ML_DSA_87_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_DSA_87_SECRETKEYBYTES
            self.signature_size = pqmagic.ML_DSA_87_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_128f):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_128f_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_128s):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_128s_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_192f):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_192f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_192f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_192f_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_192s):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_192s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_192s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_192s_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_256f):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_256f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_256f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_256f_SIGBYTES
        elif(self.label == SLH_DSA_SHA2_256s):
            self.public_key_size = pqmagic.SLH_DSA_SHA2_256s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHA2_256s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHA2_256s_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_128f):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_128f_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_128s):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_128s_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_192f):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_192f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_192f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_192f_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_192s):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_192s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_192s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_192s_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_256f):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_256f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_256f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_256f_SIGBYTES
        elif(self.label == SLH_DSA_SHAKE_256s):
            self.public_key_size = pqmagic.SLH_DSA_SHAKE_256s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SHAKE_256s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SHAKE_256s_SIGBYTES
        elif(self.label == SLH_DSA_SM3_128f):
            self.public_key_size = pqmagic.SLH_DSA_SM3_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SM3_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SM3_128f_SIGBYTES
        elif(self.label == SLH_DSA_SM3_128s):
            self.public_key_size = pqmagic.SLH_DSA_SM3_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SLH_DSA_SM3_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SLH_DSA_SM3_128s_SIGBYTES
        elif(self.label == AIGIS_SIG_1):
            self.public_key_size = pqmagic.AIGIS_SIG1_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_SIG1_SECRETKEYBYTES
            self.signature_size = pqmagic.AIGIS_SIG1_SIGBYTES
        elif(self.label == AIGIS_SIG_2):
            self.public_key_size = pqmagic.AIGIS_SIG2_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_SIG2_SECRETKEYBYTES
            self.signature_size = pqmagic.AIGIS_SIG2_SIGBYTES
        elif(self.label == AIGIS_SIG_3):
            self.public_key_size = pqmagic.AIGIS_SIG3_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_SIG3_SECRETKEYBYTES
            self.signature_size = pqmagic.AIGIS_SIG3_SIGBYTES
        elif(self.label == DILITHIUM_2):
            self.public_key_size = pqmagic.DILITHIUM2_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.DILITHIUM2_SECRETKEYBYTES
            self.signature_size = pqmagic.DILITHIUM2_SIGBYTES
        elif(self.label == DILITHIUM_3):
            self.public_key_size = pqmagic.DILITHIUM3_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.DILITHIUM3_SECRETKEYBYTES
            self.signature_size = pqmagic.DILITHIUM3_SIGBYTES
        elif(self.label == DILITHIUM_5):
            self.public_key_size = pqmagic.DILITHIUM5_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.DILITHIUM5_SECRETKEYBYTES
            self.signature_size = pqmagic.DILITHIUM5_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_128f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_128s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_192f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_192f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_192f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_192s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_192s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_192s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_256f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_256f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_256f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            self.public_key_size = pqmagic.SPHINCS_A_SHA2_256s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHA2_256s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHA2_256s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_128f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_128s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_192f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_192f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_192s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_192s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_256f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_256f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            self.public_key_size = pqmagic.SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SHAKE_256s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SHAKE_256s_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            self.public_key_size = pqmagic.SPHINCS_A_SM3_128f_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SM3_128f_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SM3_128f_SIGBYTES
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            self.public_key_size = pqmagic.SPHINCS_A_SM3_128s_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.SPHINCS_A_SM3_128s_SECRETKEYBYTES
            self.signature_size = pqmagic.SPHINCS_A_SM3_128s_SIGBYTES
    
        self.pk = <unsigned char *>malloc(self.public_key_size)
        self.sk = <unsigned char *>malloc(self.secret_key_size)
    
    def keypair(self):
        if(self.label == ML_DSA_44):
            assert pqmagic.pqmagic_ml_dsa_44_std_keypair(self.pk, self.sk) == 0
        elif(self.label == ML_DSA_65):
            assert pqmagic.pqmagic_ml_dsa_65_std_keypair(self.pk, self.sk) == 0
        elif(self.label == ML_DSA_87):
            assert pqmagic.pqmagic_ml_dsa_87_std_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_128f):
            assert pqmagic.pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_128s):
            assert pqmagic.pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_192f):
            assert pqmagic.pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_192s):
            assert pqmagic.pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_256f):
            assert pqmagic.pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHA2_256s):
            assert pqmagic.pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_128f):
            assert pqmagic.pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_128s):
            assert pqmagic.pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_192f):
            assert pqmagic.pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_192s):
            assert pqmagic.pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_256f):
            assert pqmagic.pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SHAKE_256s):
            assert pqmagic.pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SM3_128f):
            assert pqmagic.pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SLH_DSA_SM3_128s):
            assert pqmagic.pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_SIG_1):
            assert pqmagic.pqmagic_aigis_sig1_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_SIG_2):
            assert pqmagic.pqmagic_aigis_sig2_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_SIG_3):
            assert pqmagic.pqmagic_aigis_sig3_std_keypair(self.pk, self.sk) == 0
        elif(self.label == DILITHIUM_2):
            assert pqmagic.pqmagic_dilithium2_std_keypair(self.pk, self.sk) == 0
        elif(self.label == DILITHIUM_3):
            assert pqmagic.pqmagic_dilithium3_std_keypair(self.pk, self.sk) == 0
        elif(self.label == DILITHIUM_5):
            assert pqmagic.pqmagic_dilithium5_std_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            assert pqmagic.pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            assert pqmagic.pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            assert pqmagic.pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            assert pqmagic.pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            assert pqmagic.pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            assert pqmagic.pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            assert pqmagic.pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            assert pqmagic.pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            assert pqmagic.pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            assert pqmagic.pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            assert pqmagic.pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            assert pqmagic.pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            assert pqmagic.pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(self.pk, self.sk) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            assert pqmagic.pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(self.pk, self.sk) == 0
        
        return self.pk[:self.public_key_size], self.sk[:self.secret_key_size]
    
    # Could be performed with either the self.sk or the input sk parameter,
    # but please enter the sk explicitly when ctx is null but sk is not: sign(m, sk = b'xxxx').
    def sign(self, bytes m, bytes ctx = b'', bytes sk = b''):

        cdef size_t mlen = <size_t>len(m)
        cdef size_t ctxlen = <size_t>len(ctx)
        cdef size_t siglen = self.signature_size
        
        cdef unsigned char *sig = <unsigned char *>malloc(siglen)
        cdef unsigned char *m_ptr = <unsigned char *>m
        cdef unsigned char *ctx_ptr = <unsigned char *>ctx
        cdef unsigned char *sk_ptr

        if(sk):
            if(<size_t>len(sk) != self.secret_key_size):
                print("Invalid sk length!")
                return PQMAGIC_FAILURE 
            sk_ptr = <unsigned char *>sk
        else:
            sk_ptr = self.sk

        if(self.label == ML_DSA_44):
            assert pqmagic.pqmagic_ml_dsa_44_std_signature(sig, &siglen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == ML_DSA_65):
            assert pqmagic.pqmagic_ml_dsa_65_std_signature(sig, &siglen, m_ptr, mlen,  ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == ML_DSA_87):
            assert pqmagic.pqmagic_ml_dsa_87_std_signature(sig, &siglen, m_ptr, mlen,  ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_128f):
            assert pqmagic.pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_128s):
            assert pqmagic.pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_192f):
            assert pqmagic.pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_192s):
            assert pqmagic.pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_256f):
            assert pqmagic.pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_256s):
            assert pqmagic.pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_128f):
            assert pqmagic.pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_128s):
            assert pqmagic.pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_192f):
            assert pqmagic.pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_192s):
            assert pqmagic.pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_256f):
            assert pqmagic.pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_256s):
            assert pqmagic.pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SM3_128f):
            assert pqmagic.pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SM3_128s):
            assert pqmagic.pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_1):
            assert pqmagic.pqmagic_aigis_sig1_std_signature(sig, &siglen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_2):
            assert pqmagic.pqmagic_aigis_sig2_std_signature(sig, &siglen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_3):
            assert pqmagic.pqmagic_aigis_sig3_std_signature(sig, &siglen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_2):
            assert pqmagic.pqmagic_dilithium2_std_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_3):
            assert pqmagic.pqmagic_dilithium3_std_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_5):
            assert pqmagic.pqmagic_dilithium5_std_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            assert pqmagic.pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            assert pqmagic.pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            assert pqmagic.pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            assert pqmagic.pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            assert pqmagic.pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            assert pqmagic.pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            assert pqmagic.pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            assert pqmagic.pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            assert pqmagic.pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            assert pqmagic.pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            assert pqmagic.pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            assert pqmagic.pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            assert pqmagic.pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            assert pqmagic.pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(sig, &siglen, m_ptr, mlen, sk_ptr) == 0
        
        result = sig[:siglen]
        free(sig)
        return result  
    
    # return 0 if verification success, or return error code (neg number).
    # Could be performed with either the self.pk or the input pk parameter,
    # but please enter the pk explicitly when ctx is null but pk is not: verify(sig, m, pk = b'xxxx').
    def verify(self, bytes sig, bytes m, bytes ctx = b'', bytes pk = b''):
        try:
            assert <size_t>len(sig) == self.signature_size
        except:
            print('Invalid length!')
            return PQMAGIC_FAILURE
        
        cdef size_t mlen = <size_t>len(m)
        cdef size_t ctxlen = <size_t>len(ctx)
        cdef size_t siglen = self.signature_size

        cdef unsigned char *m_ptr = <unsigned char *>m
        cdef unsigned char *sig_ptr = <unsigned char *>sig
        cdef unsigned char *ctx_ptr = <unsigned char *>ctx
        cdef unsigned char *pk_ptr

        if(pk):
            if(<size_t>len(pk) != self.public_key_size):
                print("Invalid pk length!")
                return PQMAGIC_FAILURE
            pk_ptr = <unsigned char *>pk
        else:
            pk_ptr = self.pk

        if(self.label == ML_DSA_44):
            return pqmagic.pqmagic_ml_dsa_44_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == ML_DSA_65):
            return pqmagic.pqmagic_ml_dsa_65_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == ML_DSA_87):
            return pqmagic.pqmagic_ml_dsa_87_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic.pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic.pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic.pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic.pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic.pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic.pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic.pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic.pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic.pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic.pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic.pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic.pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic.pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic.pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic.pqmagic_aigis_sig1_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic.pqmagic_aigis_sig2_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic.pqmagic_aigis_sig3_std_verify(sig_ptr, siglen, m_ptr, mlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == DILITHIUM_2):
            return pqmagic.pqmagic_dilithium2_std_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == DILITHIUM_3):
            return pqmagic.pqmagic_dilithium3_std_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == DILITHIUM_5):
            return pqmagic.pqmagic_dilithium5_std_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic.pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic.pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic.pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic.pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic.pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic.pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic.pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic.pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic.pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic.pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic.pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic.pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic.pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic.pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(sig_ptr, siglen, m_ptr, mlen, pk_ptr)
    
    # Could be performed with either the self.sk or the input sk parameter,
    # but please enter the sk explicitly when ctx is null but sk is not: sign_pack(m, sk = b'xxxx').
    def sign_pack(self, bytes m, bytes ctx = b'', bytes sk = b''):
        cdef size_t mlen = <size_t>len(m)
        cdef size_t ctxlen = <size_t>len(ctx)
        cdef size_t smlen = self.signature_size + mlen + ctxlen

        cdef unsigned char *sm = <unsigned char *>malloc(smlen)
        cdef unsigned char *m_ptr = <unsigned char *>m
        cdef unsigned char *ctx_ptr = <unsigned char *>ctx
        cdef unsigned char *sk_ptr

        if(sk):
            if(<size_t>len(sk) != self.secret_key_size):
                print("Invalid sk length!")
                return PQMAGIC_FAILURE
            sk_ptr = <unsigned char *>sk
        else:
            sk_ptr = self.sk
        
        if(self.label == ML_DSA_44):
            assert pqmagic.pqmagic_ml_dsa_44_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == ML_DSA_65):
            assert pqmagic.pqmagic_ml_dsa_65_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == ML_DSA_87):
            assert pqmagic.pqmagic_ml_dsa_87_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_128f):
            assert pqmagic.pqmagic_slh_dsa_sha2_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_128s):
            assert pqmagic.pqmagic_slh_dsa_sha2_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_192f):
            assert pqmagic.pqmagic_slh_dsa_sha2_192f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_192s):
            assert pqmagic.pqmagic_slh_dsa_sha2_192s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_256f):
            assert pqmagic.pqmagic_slh_dsa_sha2_256f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHA2_256s):
            assert pqmagic.pqmagic_slh_dsa_sha2_256s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_128f):
            assert pqmagic.pqmagic_slh_dsa_shake_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_128s):
            assert pqmagic.pqmagic_slh_dsa_shake_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_192f):
            assert pqmagic.pqmagic_slh_dsa_shake_192f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_192s):
            assert pqmagic.pqmagic_slh_dsa_shake_192s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_256f):
            assert pqmagic.pqmagic_slh_dsa_shake_256f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SHAKE_256s):
            assert pqmagic.pqmagic_slh_dsa_shake_256s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SM3_128f):
            assert pqmagic.pqmagic_slh_dsa_sm3_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SLH_DSA_SM3_128s):
            assert pqmagic.pqmagic_slh_dsa_sm3_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_1):
            assert pqmagic.pqmagic_aigis_sig1_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_2):
            assert pqmagic.pqmagic_aigis_sig2_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == AIGIS_SIG_3):
            assert pqmagic.pqmagic_aigis_sig3_std(sm, &smlen, m_ptr, mlen, ctx_ptr, ctxlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_2):
            assert pqmagic.pqmagic_dilithium2_std(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_3):
            assert pqmagic.pqmagic_dilithium3_std(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == DILITHIUM_5):
            assert pqmagic.pqmagic_dilithium5_std(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            assert pqmagic.pqmagic_sphincs_a_sha2_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            assert pqmagic.pqmagic_sphincs_a_sha2_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            assert pqmagic.pqmagic_sphincs_a_sha2_192f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            assert pqmagic.pqmagic_sphincs_a_sha2_192s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            assert pqmagic.pqmagic_sphincs_a_sha2_256f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            assert pqmagic.pqmagic_sphincs_a_sha2_256s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            assert pqmagic.pqmagic_sphincs_a_shake_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            assert pqmagic.pqmagic_sphincs_a_shake_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            assert pqmagic.pqmagic_sphincs_a_shake_192f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            assert pqmagic.pqmagic_sphincs_a_shake_192s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            assert pqmagic.pqmagic_sphincs_a_shake_256f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            assert pqmagic.pqmagic_sphincs_a_shake_256s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            assert pqmagic.pqmagic_sphincs_a_sm3_128f_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            assert pqmagic.pqmagic_sphincs_a_sm3_128s_simple_std_sign(sm, &smlen, m_ptr, mlen, sk_ptr) == 0
        
        result = sm[:smlen]
        free(sm)
        return result
    
    # return 0 if verification success, or return error code (neg number).
    # Could be performed with either the self.pk or the input pk parameter,
    # but please enter the pk explicitly when ctx is null but pk is not: sign(m, sm, pk = b'xxx').
    def open(self, bytes m, bytes sm, bytes ctx = b'', bytes pk = b''):
        cdef size_t mlen = <size_t>len(m)
        cdef size_t ctxlen = <size_t>len(ctx)
        cdef size_t smlen = self.signature_size + mlen
        
        try:
            assert <size_t>len(sm) == smlen
        except:
            print("Invalid length!")
            return PQMAGIC_FAILURE
        
        cdef unsigned char *m_ptr = <unsigned char *>m
        cdef unsigned char *sm_ptr = <unsigned char *>sm
        cdef unsigned char *ctx_ptr = <unsigned char *>ctx
        cdef unsigned char *pk_ptr

        if(pk):
            if(<size_t>len(pk) != self.public_key_size):
                print("Invalid pk length!")
                return PQMAGIC_FAILURE
            pk_ptr = <unsigned char *>pk
        else:
            pk_ptr = self.pk

        if(self.label == ML_DSA_44):
            return pqmagic.pqmagic_ml_dsa_44_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == ML_DSA_65):
            return pqmagic.pqmagic_ml_dsa_65_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == ML_DSA_87):
            return pqmagic.pqmagic_ml_dsa_87_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx_ptr, ctxlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic.pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic.pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic.pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic.pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic.pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic.pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic.pqmagic_slh_dsa_shake_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic.pqmagic_slh_dsa_shake_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic.pqmagic_slh_dsa_shake_192f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic.pqmagic_slh_dsa_shake_192s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic.pqmagic_slh_dsa_shake_256f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic.pqmagic_slh_dsa_shake_256s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic.pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic.pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic.pqmagic_aigis_sig1_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx, ctxlen, pk_ptr)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic.pqmagic_aigis_sig2_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx, ctxlen, pk_ptr)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic.pqmagic_aigis_sig3_std_open(m_ptr, &mlen, sm_ptr, smlen, ctx, ctxlen, pk_ptr)
        elif(self.label == DILITHIUM_2):
            return pqmagic.pqmagic_dilithium2_std_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == DILITHIUM_3):
            return pqmagic.pqmagic_dilithium3_std_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == DILITHIUM_5):
            return pqmagic.pqmagic_dilithium5_std_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic.pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic.pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic.pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic.pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic.pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic.pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic.pqmagic_sphincs_a_shake_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic.pqmagic_sphincs_a_shake_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic.pqmagic_sphincs_a_shake_192f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic.pqmagic_sphincs_a_shake_192s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic.pqmagic_sphincs_a_shake_256f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic.pqmagic_sphincs_a_shake_256s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic.pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic.pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(m_ptr, &mlen, sm_ptr, smlen, pk_ptr)

    def __dealloc__(self):
        if self.pk:
            free(self.pk)
        if self.sk:
            free(self.sk)

cdef class KEM:
    cdef public kem_label label
    cdef unsigned char *pk
    cdef unsigned char *sk
    cdef public size_t public_key_size
    cdef public size_t secret_key_size
    cdef public size_t ciphertext_size
    cdef public size_t shared_secret_size

    def __cinit__(self, str name):
        if name not in kem_label_map:  
            raise ValueError("Invalid algorithm name.")  
        self.label = kem_label_map[name]

        if(self.label == ML_KEM_512):
            self.public_key_size = pqmagic.ML_KEM_512_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_KEM_512_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.ML_KEM_512_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.ML_KEM_512_SSBYTES
        elif(self.label == ML_KEM_768):
            self.public_key_size = pqmagic.ML_KEM_768_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_KEM_768_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.ML_KEM_768_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.ML_KEM_768_SSBYTES
        elif(self.label == ML_KEM_1024):
            self.public_key_size = pqmagic.ML_KEM_1024_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.ML_KEM_1024_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.ML_KEM_1024_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.ML_KEM_1024_SSBYTES
        elif(self.label == KYBER_512):
            self.public_key_size = pqmagic.KYBER512_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.KYBER512_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.KYBER512_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.KYBER512_SSBYTES
        elif(self.label == KYBER_768):
            self.public_key_size = pqmagic.KYBER768_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.KYBER768_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.KYBER768_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.KYBER768_SSBYTES
        elif(self.label == KYBER_1024):
            self.public_key_size = pqmagic.KYBER1024_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.KYBER1024_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.KYBER1024_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.KYBER1024_SSBYTES
        elif(self.label == AIGIS_ENC_1):
            self.public_key_size = pqmagic.AIGIS_ENC_1_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_ENC_1_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.AIGIS_ENC_1_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.AIGIS_ENC_1_SSBYTES
        elif(self.label == AIGIS_ENC_2):
            self.public_key_size = pqmagic.AIGIS_ENC_2_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_ENC_2_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.AIGIS_ENC_2_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.AIGIS_ENC_2_SSBYTES
        elif(self.label == AIGIS_ENC_3):
            self.public_key_size = pqmagic.AIGIS_ENC_3_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_ENC_3_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.AIGIS_ENC_3_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.AIGIS_ENC_3_SSBYTES
        elif(self.label == AIGIS_ENC_4):
            self.public_key_size = pqmagic.AIGIS_ENC_4_PUBLICKEYBYTES
            self.secret_key_size = pqmagic.AIGIS_ENC_4_SECRETKEYBYTES
            self.ciphertext_size = pqmagic.AIGIS_ENC_4_CIPHERTEXTBYTES
            self.shared_secret_size = pqmagic.AIGIS_ENC_4_SSBYTES

        self.pk = <unsigned char *>malloc(self.public_key_size)
        self.sk = <unsigned char *>malloc(self.secret_key_size)

    def keypair(self):
        if(self.label == ML_KEM_512):
            assert pqmagic.pqmagic_ml_kem_512_std_keypair(self.pk, self.sk) == 0
        elif(self.label == ML_KEM_768):
            assert pqmagic.pqmagic_ml_kem_768_std_keypair(self.pk, self.sk) == 0
        elif(self.label == ML_KEM_1024):
            assert pqmagic.pqmagic_ml_kem_1024_std_keypair(self.pk, self.sk) == 0
        elif(self.label == KYBER_512):
            assert pqmagic.pqmagic_kyber512_std_keypair(self.pk, self.sk) == 0
        elif(self.label == KYBER_768):
            assert pqmagic.pqmagic_kyber768_std_keypair(self.pk, self.sk) == 0
        elif(self.label == KYBER_1024):
            assert pqmagic.pqmagic_kyber1024_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_ENC_1):
            assert pqmagic.pqmagic_aigis_enc_1_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_ENC_2):
            assert pqmagic.pqmagic_aigis_enc_2_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_ENC_3):
            assert pqmagic.pqmagic_aigis_enc_3_std_keypair(self.pk, self.sk) == 0
        elif(self.label == AIGIS_ENC_4):
            assert pqmagic.pqmagic_aigis_enc_4_std_keypair(self.pk, self.sk) == 0

        return self.pk[:self.public_key_size], self.sk[:self.secret_key_size]
    
    # Could be performed with either the self.pk or the input pk parameter.
    def encaps(self, bytes pk = b''):
        cdef unsigned char *ss = <unsigned char *>malloc(self.shared_secret_size)
        cdef unsigned char *ct = <unsigned char *>malloc(self.ciphertext_size)
        cdef unsigned char *pk_ptr

        if(pk):
            if(<size_t>len(pk) != self.public_key_size):
                print("Invalid pk length!")
                return PQMAGIC_FAILURE
            pk_ptr = <unsigned char *>pk
        else:
            pk_ptr = self.pk
        
        if(self.label == ML_KEM_512):
            assert pqmagic.pqmagic_ml_kem_512_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == ML_KEM_768):
            assert pqmagic.pqmagic_ml_kem_768_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == ML_KEM_1024):
            assert pqmagic.pqmagic_ml_kem_1024_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == KYBER_512):
            assert pqmagic.pqmagic_kyber512_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == KYBER_768):
            assert pqmagic.pqmagic_kyber768_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == KYBER_1024):
            assert pqmagic.pqmagic_kyber1024_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == AIGIS_ENC_1):
            assert pqmagic.pqmagic_aigis_enc_1_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == AIGIS_ENC_2):
            assert pqmagic.pqmagic_aigis_enc_2_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == AIGIS_ENC_3):
            assert pqmagic.pqmagic_aigis_enc_3_std_enc(ct, ss, pk_ptr) == 0
        elif(self.label == AIGIS_ENC_4):
            assert pqmagic.pqmagic_aigis_enc_4_std_enc(ct, ss, pk_ptr) == 0
        
        result = ct[:self.ciphertext_size], ss[:self.shared_secret_size]
        free(ss)
        free(ct)
        return result

    # Could be performed with either the self.sk or the input sk parameter.
    def decaps(self, bytes ct, bytes sk = b''):
        try:
            assert <size_t>len(ct) == self.ciphertext_size
        except:
            print("Invalid ct length!")
            return PQMAGIC_FAILURE

        cdef unsigned char *ss = <unsigned char *>malloc(self.shared_secret_size)
        cdef unsigned char *ct_ptr = <unsigned char *>ct
        cdef unsigned char *sk_ptr

        if(sk):
            if(<size_t>len(sk) != self.secret_key_size):
                print("Invalid sk length!")
                return PQMAGIC_FAILURE
            sk_ptr = <unsigned char *>sk
        else:
            sk_ptr = self.sk
        
        if(self.label == ML_KEM_512):
            assert pqmagic.pqmagic_ml_kem_512_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == ML_KEM_768):
            assert pqmagic.pqmagic_ml_kem_768_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == ML_KEM_1024):
            assert pqmagic.pqmagic_ml_kem_1024_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == KYBER_512):
            assert pqmagic.pqmagic_kyber512_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == KYBER_768):
            assert pqmagic.pqmagic_kyber768_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == KYBER_1024):
            assert pqmagic.pqmagic_kyber1024_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == AIGIS_ENC_1):
            assert pqmagic.pqmagic_aigis_enc_1_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == AIGIS_ENC_2):
            assert pqmagic.pqmagic_aigis_enc_2_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == AIGIS_ENC_3):
            assert pqmagic.pqmagic_aigis_enc_3_std_dec(ss, ct_ptr, sk_ptr) == 0
        elif(self.label == AIGIS_ENC_4):
            assert pqmagic.pqmagic_aigis_enc_4_std_dec(ss, ct_ptr, sk_ptr) == 0

        result = ss[:self.shared_secret_size]
        free(ss)
        return result
    
    def __dealloc__(self):
        if self.pk:
            free(self.pk)
        if self.sk:
            free(self.sk)