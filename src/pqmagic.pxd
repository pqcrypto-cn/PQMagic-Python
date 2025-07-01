# pymagic.pxd

cdef extern from "pqmagic_api.h":
    
    cdef int ML_DSA_44_PUBLICKEYBYTES = 1312
    cdef int ML_DSA_44_SECRETKEYBYTES = 2560
    cdef int ML_DSA_44_SIGBYTES = 2420
    int pqmagic_ml_dsa_44_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_dsa_44_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_dsa_44_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_44_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_ml_dsa_44_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_ml_dsa_44_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_ml_dsa_44_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_44_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)

    cdef int ML_DSA_65_PUBLICKEYBYTES = 1952
    cdef int ML_DSA_65_SECRETKEYBYTES = 4032
    cdef int ML_DSA_65_SIGBYTES = 3309
    int pqmagic_ml_dsa_65_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_dsa_65_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_dsa_65_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_65_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_ml_dsa_65_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_ml_dsa_65_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_ml_dsa_65_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_65_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)

    cdef int ML_DSA_87_PUBLICKEYBYTES = 2592
    cdef int ML_DSA_87_SECRETKEYBYTES = 4896
    cdef int ML_DSA_87_SIGBYTES = 4627
    int pqmagic_ml_dsa_87_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_dsa_87_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_dsa_87_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_87_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_ml_dsa_87_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_ml_dsa_87_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_ml_dsa_87_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_ml_dsa_87_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)

    cdef int DILITHIUM2_PUBLICKEYBYTES = 1312
    cdef int DILITHIUM2_SECRETKEYBYTES = 2528
    cdef int DILITHIUM2_SIGBYTES = 2420
    int pqmagic_dilithium2_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_dilithium2_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_dilithium2_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium2_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_dilithium2_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_dilithium2_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium2_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int DILITHIUM3_PUBLICKEYBYTES = 1952
    cdef int DILITHIUM3_SECRETKEYBYTES = 4000
    cdef int DILITHIUM3_SIGBYTES = 3293
    int pqmagic_dilithium3_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_dilithium3_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_dilithium3_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium3_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_dilithium3_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_dilithium3_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium3_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int DILITHIUM5_PUBLICKEYBYTES = 2592
    cdef int DILITHIUM5_SECRETKEYBYTES = 4864
    cdef int DILITHIUM5_SIGBYTES = 4595
    int pqmagic_dilithium5_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_dilithium5_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_dilithium5_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium5_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, unsigned char *sign_coins, const unsigned char *sk)
    int pqmagic_dilithium5_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_dilithium5_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_dilithium5_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int AIGIS_SIG1_PUBLICKEYBYTES = 1056
    cdef int AIGIS_SIG1_SECRETKEYBYTES = 2448
    cdef int AIGIS_SIG1_SIGBYTES = 1852
    int pqmagic_aigis_sig1_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_sig1_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_sig1_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig1_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_aigis_sig1_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_aigis_sig1_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_aigis_sig1_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig1_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)

    cdef int AIGIS_SIG2_PUBLICKEYBYTES = 1312
    cdef int AIGIS_SIG2_SECRETKEYBYTES = 3376
    cdef int AIGIS_SIG2_SIGBYTES = 2445
    int pqmagic_aigis_sig2_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_sig2_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_sig2_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig2_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_aigis_sig2_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_aigis_sig2_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_aigis_sig2_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig2_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    
    cdef int AIGIS_SIG3_PUBLICKEYBYTES = 1568
    cdef int AIGIS_SIG3_SECRETKEYBYTES = 3888
    cdef int AIGIS_SIG3_SIGBYTES = 3046
    int pqmagic_aigis_sig3_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_sig3_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_sig3_std_signature(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig3_std_signature_internal(unsigned char *sig, size_t *siglen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_aigis_sig3_std_verify(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)
    int pqmagic_aigis_sig3_std_verify_internal(const unsigned char *sig, size_t siglen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_aigis_sig3_std(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *sk)
    int pqmagic_aigis_sig3_std_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *ctx, size_t ctx_len, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_128f_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SHA2_128f_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SHA2_128f_SIGBYTES = 17088
    int pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_128s_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SHA2_128s_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SHA2_128s_SIGBYTES = 7856
    int pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_192f_PUBLICKEYBYTES = 48
    cdef int SLH_DSA_SHA2_192f_SECRETKEYBYTES = 96
    cdef int SLH_DSA_SHA2_192f_SIGBYTES = 35664
    int pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_192f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_192s_PUBLICKEYBYTES = 48
    cdef int SLH_DSA_SHA2_192s_SECRETKEYBYTES = 96
    cdef int SLH_DSA_SHA2_192s_SIGBYTES = 16224
    int pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_192s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_256f_PUBLICKEYBYTES = 64
    cdef int SLH_DSA_SHA2_256f_SECRETKEYBYTES = 128
    cdef int SLH_DSA_SHA2_256f_SIGBYTES = 49856
    int pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_256f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHA2_256s_PUBLICKEYBYTES = 64
    cdef int SLH_DSA_SHA2_256s_SECRETKEYBYTES = 128
    cdef int SLH_DSA_SHA2_256s_SIGBYTES = 29792
    int pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sha2_256s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_128f_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SHAKE_128f_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SHAKE_128f_SIGBYTES = 17088
    int pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_128s_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SHAKE_128s_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SHAKE_128s_SIGBYTES = 7856
    int pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_192f_PUBLICKEYBYTES = 48
    cdef int SLH_DSA_SHAKE_192f_SECRETKEYBYTES = 96
    cdef int SLH_DSA_SHAKE_192f_SIGBYTES = 35664
    int pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_192f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_192f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_192s_PUBLICKEYBYTES = 48
    cdef int SLH_DSA_SHAKE_192s_SECRETKEYBYTES = 96
    cdef int SLH_DSA_SHAKE_192s_SIGBYTES = 16224
    int pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_192s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_192s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_256f_PUBLICKEYBYTES = 64
    cdef int SLH_DSA_SHAKE_256f_SECRETKEYBYTES = 128
    cdef int SLH_DSA_SHAKE_256f_SIGBYTES = 49856
    int pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_256f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_256f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SHAKE_256s_PUBLICKEYBYTES = 64
    cdef int SLH_DSA_SHAKE_256s_SECRETKEYBYTES = 128
    cdef int SLH_DSA_SHAKE_256s_SIGBYTES = 29792
    int pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_shake_256s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_shake_256s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SM3_128f_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SM3_128f_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SM3_128f_SIGBYTES = 17088
    int pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sm3_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SLH_DSA_SM3_128s_PUBLICKEYBYTES = 32
    cdef int SLH_DSA_SM3_128s_SECRETKEYBYTES = 64
    cdef int SLH_DSA_SM3_128s_SIGBYTES = 7856
    int pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_slh_dsa_sm3_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_128f_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SHA2_128f_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SHA2_128f_SIGBYTES = 16720
    int pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_128s_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SHA2_128s_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SHA2_128s_SIGBYTES = 6880
    int pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_192f_PUBLICKEYBYTES = 48
    cdef int SPHINCS_A_SHA2_192f_SECRETKEYBYTES = 96
    cdef int SPHINCS_A_SHA2_192f_SIGBYTES = 34896
    int pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_192f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_192s_PUBLICKEYBYTES = 48
    cdef int SPHINCS_A_SHA2_192s_SECRETKEYBYTES = 96
    cdef int SPHINCS_A_SHA2_192s_SIGBYTES = 14568
    int pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_192s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_256f_PUBLICKEYBYTES = 64
    cdef int SPHINCS_A_SHA2_256f_SECRETKEYBYTES = 128
    cdef int SPHINCS_A_SHA2_256f_SIGBYTES = 49312
    int pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_256f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHA2_256s_PUBLICKEYBYTES = 64
    cdef int SPHINCS_A_SHA2_256s_SECRETKEYBYTES = 128
    cdef int SPHINCS_A_SHA2_256s_SIGBYTES = 27232
    int pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sha2_256s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_128f_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SHAKE_128f_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SHAKE_128f_SIGBYTES = 16720
    int pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_128s_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SHAKE_128s_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SHAKE_128s_SIGBYTES = 6880
    int pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_192f_PUBLICKEYBYTES = 48
    cdef int SPHINCS_A_SHAKE_192f_SECRETKEYBYTES = 96
    cdef int SPHINCS_A_SHAKE_192f_SIGBYTES = 34896
    int pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_192f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_192f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_192s_PUBLICKEYBYTES = 48
    cdef int SPHINCS_A_SHAKE_192s_SECRETKEYBYTES = 96
    cdef int SPHINCS_A_SHAKE_192s_SIGBYTES = 14568
    int pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_192s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_192s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_256f_PUBLICKEYBYTES = 64
    cdef int SPHINCS_A_SHAKE_256f_SECRETKEYBYTES = 128
    cdef int SPHINCS_A_SHAKE_256f_SIGBYTES = 49312
    int pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_256f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_256f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SHAKE_256s_PUBLICKEYBYTES = 64
    cdef int SPHINCS_A_SHAKE_256s_SECRETKEYBYTES = 128
    cdef int SPHINCS_A_SHAKE_256s_SIGBYTES = 27232
    int pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_shake_256s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_shake_256s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SM3_128f_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SM3_128f_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SM3_128f_SIGBYTES = 16720
    int pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sm3_128f_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int SPHINCS_A_SM3_128s_PUBLICKEYBYTES = 32
    cdef int SPHINCS_A_SM3_128s_SECRETKEYBYTES = 64
    cdef int SPHINCS_A_SM3_128s_SIGBYTES = 6880
    int pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(const unsigned char *sm, size_t smlen, const unsigned char *m, size_t mlen, const unsigned char *pk)
    int pqmagic_sphincs_a_sm3_128s_simple_std_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk)
    int pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk)

    cdef int ML_KEM_512_PUBLICKEYBYTES = 800
    cdef int ML_KEM_512_SECRETKEYBYTES = 1632
    cdef int ML_KEM_512_CIPHERTEXTBYTES = 768
    cdef int ML_KEM_512_SSBYTES = 32
    int pqmagic_ml_kem_512_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_kem_512_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_kem_512_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_ml_kem_512_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_ml_kem_512_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int ML_KEM_768_PUBLICKEYBYTES = 1184
    cdef int ML_KEM_768_SECRETKEYBYTES = 2400
    cdef int ML_KEM_768_CIPHERTEXTBYTES = 1088
    cdef int ML_KEM_768_SSBYTES = 32
    int pqmagic_ml_kem_768_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_kem_768_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_kem_768_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_ml_kem_768_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_ml_kem_768_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int ML_KEM_1024_PUBLICKEYBYTES = 1568
    cdef int ML_KEM_1024_SECRETKEYBYTES = 3168
    cdef int ML_KEM_1024_CIPHERTEXTBYTES = 1568
    cdef int ML_KEM_1024_SSBYTES = 32
    int pqmagic_ml_kem_1024_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_ml_kem_1024_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_ml_kem_1024_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_ml_kem_1024_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_ml_kem_1024_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int KYBER512_PUBLICKEYBYTES = 800
    cdef int KYBER512_SECRETKEYBYTES = 1632
    cdef int KYBER512_CIPHERTEXTBYTES = 768
    cdef int KYBER512_SSBYTES = 32
    int pqmagic_kyber512_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_kyber512_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_kyber512_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_kyber512_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_kyber512_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int KYBER768_PUBLICKEYBYTES = 1184
    cdef int KYBER768_SECRETKEYBYTES = 2400
    cdef int KYBER768_CIPHERTEXTBYTES = 1088
    cdef int KYBER768_SSBYTES = 32
    int pqmagic_kyber768_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_kyber768_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_kyber768_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_kyber768_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_kyber768_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int KYBER1024_PUBLICKEYBYTES = 1568
    cdef int KYBER1024_SECRETKEYBYTES = 3168
    cdef int KYBER1024_CIPHERTEXTBYTES = 1568
    cdef int KYBER1024_SSBYTES = 32
    int pqmagic_kyber1024_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_kyber1024_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_kyber1024_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_kyber1024_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_kyber1024_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
    
    cdef int AIGIS_ENC_1_PUBLICKEYBYTES = 672
    cdef int AIGIS_ENC_1_SECRETKEYBYTES = 1568
    cdef int AIGIS_ENC_1_CIPHERTEXTBYTES = 736
    cdef int AIGIS_ENC_1_SSBYTES = 32
    int pqmagic_aigis_enc_1_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_enc_1_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_enc_1_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_aigis_enc_1_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_aigis_enc_1_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int AIGIS_ENC_2_PUBLICKEYBYTES = 896
    cdef int AIGIS_ENC_2_SECRETKEYBYTES = 2208
    cdef int AIGIS_ENC_2_CIPHERTEXTBYTES = 992
    cdef int AIGIS_ENC_2_SSBYTES = 32
    int pqmagic_aigis_enc_2_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_enc_2_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_enc_2_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_aigis_enc_2_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_aigis_enc_2_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int AIGIS_ENC_3_PUBLICKEYBYTES = 992
    cdef int AIGIS_ENC_3_SECRETKEYBYTES = 2304
    cdef int AIGIS_ENC_3_CIPHERTEXTBYTES = 1056
    cdef int AIGIS_ENC_3_SSBYTES = 32
    int pqmagic_aigis_enc_3_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_enc_3_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_enc_3_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_aigis_enc_3_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_aigis_enc_3_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)

    cdef int AIGIS_ENC_4_PUBLICKEYBYTES = 1440
    cdef int AIGIS_ENC_4_SECRETKEYBYTES = 3168
    cdef int AIGIS_ENC_4_CIPHERTEXTBYTES = 1568
    cdef int AIGIS_ENC_4_SSBYTES = 32
    int pqmagic_aigis_enc_4_std_keypair(unsigned char *pk, unsigned char *sk)
    int pqmagic_aigis_enc_4_std_keypair_internal(unsigned char *pk, unsigned char *sk, unsigned char *keypair_coins)
    int pqmagic_aigis_enc_4_std_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
    int pqmagic_aigis_enc_4_std_enc_internal(unsigned char *ct, unsigned char *ss, const unsigned char *pk, unsigned char *kem_enc_coins)
    int pqmagic_aigis_enc_4_std_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
