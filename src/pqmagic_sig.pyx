# pqmagic_sig.pyx

from pqmagic_wrapper import *

cdef enum algo_label:
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


cdef class SIG:
    cdef algo_label label
    cdef unsigned char *pk
    cdef unsigned char *sk

    def __cinit__(self, unsigned char *name):
        try:
            self.label = algo_label(name)
        except ValueError:
            raise ValueError("Invalid algorithm name.")
        
        return keypair(self.pk, self.sk)
    
    def pqmagic_status keypair(self, unsigned char *pk, unsigned char *sk):
        if(self.label == ML_DSA_44):
            return pqmagic_ml_dsa_44_std_keypair(pk, sk)
        elif(self.label == ML_DSA_65):
            return pqmagic_ml_dsa_65_std_keypair(pk, sk)
        elif(self.label == ML_DSA_87):
            return pqmagic_ml_dsa_87_std_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(pk, sk)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic_aigis_sig_1_std_keypair(pk, sk)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic_aigis_sig_2_std_keypair(pk, sk)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic_aigis_sig_3_std_keypair(pk, sk)
        elif(self.label == DILITHIUM_2):
            return pqmagic_dilithium_2_std_keypair(pk, sk)
        elif(self.label == DILITHIUM_3):
            return pqmagic_dilithium_3_std_keypair(pk, sk)
        elif(self.label == DILITHIUM_5):
            return pqmagic_dilithium_5_std_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(pk, sk)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(pk, sk)
        else:
            return PQMAGIC_FAILURE
    
    def pqmagic_status sign(self, unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen):
        if(self.label == ML_DSA_44):
            return pqmagic_ml_dsa_44_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == ML_DSA_65):
            return pqmagic_ml_dsa_65_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == ML_DSA_87):
            return pqmagic_ml_dsa_87_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic_aigis_sig_1_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic_aigis_sig_2_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic_aigis_sig_3_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_2):
            return pqmagic_dilithium_2_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_3):
            return pqmagic_dilithium_3_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_5):
            return pqmagic_dilithium_5_std_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(sm, smlen, m, mlen, self.sk)
        else:
            return PQMAGIC_FAILURE
    
    def pqmagic_status verify(self, const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen):
        if(self.label == ML_DSA_44):
            return pqmagic_ml_dsa_44_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == ML_DSA_65):
            return pqmagic_ml_dsa_65_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == ML_DSA_87):
            return pqmagic_ml_dsa_87_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic_aigis_sig_1_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic_aigis_sig_2_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic_aigis_sig_3_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == DILITHIUM_2):
            return pqmagic_dilithium_2_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == DILITHIUM_3):
            return pqmagic_dilithium_3_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == DILITHIUM_5):
            return pqmagic_dilithium_5_std_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(sm, smlen, m, mlen, self.pk)
        else:
            return PQMAGIC_FAILURE
        
    def pqmagic_status sign_pack(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen):
        if(self.label == ML_DSA_44):
            return pqmagic_ml_dsa_44_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == ML_DSA_65):
            return pqmagic_ml_dsa_65_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == ML_DSA_87):
            return pqmagic_ml_dsa_87_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic_slh_dsa_sha2_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic_slh_dsa_sha2_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic_slh_dsa_sha2_192f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic_slh_dsa_sha2_192s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic_slh_dsa_sha2_256f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic_slh_dsa_sha2_256s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic_slh_dsa_shake_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic_slh_dsa_shake_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic_slh_dsa_shake_192f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic_slh_dsa_shake_192s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic_slh_dsa_shake_256f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic_slh_dsa_shake_256s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic_slh_dsa_sm3_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic_slh_dsa_sm3_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic_aigis_sig_1_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic_aigis_sig_2_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic_aigis_sig_3_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_2):
            return pqmagic_dilithium_2_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_3):
            return pqmagic_dilithium_3_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == DILITHIUM_5):
            return pqmagic_dilithium_5_std(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic_sphincs_a_sha2_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic_sphincs_a_sha2_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic_sphincs_a_sha2_192f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic_sphincs_a_sha2_192s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic_sphincs_a_sha2_256f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic_sphincs_a_sha2_256s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic_sphincs_a_shake_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic_sphincs_a_shake_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic_sphincs_a_shake_192f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic_sphincs_a_shake_192s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic_sphincs_a_shake_256f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic_sphincs_a_shake_256s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic_sphincs_a_sm3_128f_simple_std_sign(sm, smlen, m, mlen, self.sk)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic_sphincs_a_sm3_128s_simple_std_sign(sm, smlen, m, mlen, self.sk)
        else:
            return PQMAGIC_FAILURE


    def pqmagic_status open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen):
        if(self.label == ML_DSA_44):
            return pqmagic_ml_dsa_44_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == ML_DSA_65):
            return pqmagic_ml_dsa_65_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == ML_DSA_87):
            return pqmagic_ml_dsa_87_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_128f):
            return pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_128s):
            return pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_192f):
            return pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_192s):
            return pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_256f):
            return pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHA2_256s):
            return pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_128f):
            return pqmagic_slh_dsa_shake_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_128s):
            return pqmagic_slh_dsa_shake_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_192f):
            return pqmagic_slh_dsa_shake_192f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_192s):
            return pqmagic_slh_dsa_shake_192s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_256f):
            return pqmagic_slh_dsa_shake_256f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SHAKE_256s):
            return pqmagic_slh_dsa_shake_256s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SM3_128f):
            return pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SLH_DSA_SM3_128s):
            return pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == AIGIS_SIG_1):
            return pqmagic_aigis_sig_1_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == AIGIS_SIG_2):
            return pqmagic_aigis_sig_2_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == AIGIS_SIG_3):
            return pqmagic_aigis_sig_3_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == DILITHIUM_2):
            return pqmagic_dilithium_2_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == DILITHIUM_3):
            return pqmagic_dilithium_3_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == DILITHIUM_5):
            return pqmagic_dilithium_5_std_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_128f):
            return pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_128s):
            return pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_192f):
            return pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_192s):
            return pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_256f):
            return pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHA2_256s):
            return pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128f):
            return pqmagic_sphincs_a_shake_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_128s):
            return pqmagic_sphincs_a_shake_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192f):
            return pqmagic_sphincs_a_shake_192f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_192s):
            return pqmagic_sphincs_a_shake_192s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256f):
            return pqmagic_sphincs_a_shake_256f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SHAKE_256s):
            return pqmagic_sphincs_a_shake_256s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SM3_128f):
            return pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        elif(self.label == SPHINCS_Alpha_SM3_128s):
            return pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(m, mlen, sm, smlen, self.pk)
        else:
            return PQMAGIC_FAILURE

    def __dealloc__(self):
        if self.pk:
            free(self.pk)
        if self.sk:
            free(self.sk)