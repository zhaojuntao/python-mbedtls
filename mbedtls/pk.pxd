"""Declarations for `mbedtls/pk.h`."""

# Copyright 2016, Mathias Laurin, Elaborated Networks GmbH
# Copyright 2018, Mathias Laurin

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Mathias Laurin, Elaborated Networks GmbH"
__license__ = "MIT License"


cdef extern from "mbedtls/md.h":
    ctypedef enum mbedtls_md_type_t:
        pass


cdef extern from "mbedtls/bignum.h":
    ctypedef enum mbedtls_mpi:
        pass

    int MBEDTLS_MPI_MAX_SIZE


cdef extern from "mbedtls/ecp.h":
    ctypedef enum mbedtls_ecp_group_id:
        MBEDTLS_ECP_DP_NONE = 0,
        MBEDTLS_ECP_DP_SECP192R1
        MBEDTLS_ECP_DP_SECP224R1
        MBEDTLS_ECP_DP_SECP256R1
        MBEDTLS_ECP_DP_SECP384R1
        MBEDTLS_ECP_DP_SECP521R1
        MBEDTLS_ECP_DP_BP256R1
        MBEDTLS_ECP_DP_BP384R1
        MBEDTLS_ECP_DP_BP512R1
        MBEDTLS_ECP_DP_CURVE25519
        MBEDTLS_ECP_DP_SECP192K1
        MBEDTLS_ECP_DP_SECP224K1
        MBEDTLS_ECP_DP_SECP256K1

    ctypedef struct mbedtls_ecp_curve_info:
        mbedtls_ecp_group_id grp_id
        int bit_size
        const char *name

    ctypedef struct mbedtls_ecp_point:
        pass

    ctypedef struct mbedtls_ecp_group:
        pass

    ctypedef struct mbedtls_ecp_keypair:
        mbedtls_ecp_group grp
        mbedtls_mpi d
        mbedtls_ecp_point Q

    int MBEDTLS_ECP_MAX_BYTES

    # Free functions
    # --------------
    const mbedtls_ecp_curve_info* mbedtls_ecp_curve_list()
    # mbedtls_ecp_grp_id_list
    # mbedtls_ecp_curve_info_from_grp_id
    # mbedtls_ecp_curve_info_from_tls_id
    # mbedtls_ecp_curve_info_from_name

    # mbedtls_ecp_point
    # -----------------
    void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
    void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
    int mbedtls_ecp_copy(
        mbedtls_ecp_point *P,
        const mbedtls_ecp_point *Q)
    # mbedtls_ecp_set_zero
    int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
    int mbedtls_ecp_point_cmp(
        const mbedtls_ecp_point *P,
        const mbedtls_ecp_point *Q)
    # mbedtls_ecp_point_read_string

    # mbedtls_ecp_group
    # -----------------
    void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
    void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
    int mbedtls_ecp_group_copy(
        mbedtls_ecp_group *dst,
        const mbedtls_ecp_group *src)
    # mbedtls_ecp_point_write_binary
    # mbedtls_ecp_point_read_binary
    # mbedtls_ecp_tls_read_point
    # mbedtls_ecp_tls_write_point
    # mbedtls_ecp_group_load
    # mbedtls_ecp_tls_read_group
    # mbedtls_ecp_tls_write_group
    # mbedtls_ecp_mul
    # mbedtls_ecp_muladd
    # mbedtls_ecp_check_pubkey
    # mbedtls_ecp_check_privkey

    # mbedtls_ecp_keypair
    # -------------------
    void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
    void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
    # mbedtls_ecp_gen_keypair_base
    int mbedtls_ecp_gen_keypair(
        mbedtls_ecp_group *grp,
        mbedtls_mpi *d,
        mbedtls_ecp_point *Q,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    # mbedtls_ecp_check_pub_priv
    int mbedtls_ecp_gen_key(
        mbedtls_ecp_group_id grp_id,
        mbedtls_ecp_keypair *key,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)


cdef extern from "mbedtls/rsa.h":
    ctypedef struct mbedtls_rsa_context:
        pass

    # mbedtls_rsa_context
    # -------------------
    # mbedtls_rsa_init
    # mbedtls_rsa_set_padding
    int mbedtls_rsa_gen_key(
        mbedtls_rsa_context *ctx,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
        unsigned int nbits, int exponent)
    int mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx)
    int mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx)
    # mbedtls_rsa_check_pub_priv
    # mbedtls_rsa_public
    # mbedtls_rsa_private
    # mbedtls_rsa_pkcs1_encrypt
    # mbedtls_rsa_rsaes_pkcs1_v15_encrypt
    # mbedtls_rsa_rsaes_oaep_encrypt
    # mbedtls_rsa_pkcs1_decrypt
    # mbedtls_rsa_rsaes_pkcs1_v15_decrypt
    # mbedtls_rsa_rsaes_oaep_decrypt
    # mbedtls_rsa_pkcs1_sign
    # mbedtls_rsa_rsassa_pkcs1_v15_sign
    # mbedtls_rsa_rsassa_pss_sign
    # mbedtls_rsa_pkcs1_verify
    # mbedtls_rsa_rsassa_pkcs1_v15_verify
    # mbedtls_rsa_rsassa_pss_verify
    # mbedtls_rsa_rsassa_pss_verify_ext
    # mbedtls_rsa_copy
    # mbedtls_rsa_free


cdef extern from "mbedtls/pk.h":
    ctypedef enum mbedtls_pk_type_t:
        pass

    ctypedef struct mbedtls_pk_rsassa_pss_options:
        pass

    ctypedef struct mbedtls_pk_info_t:
        pass
    
    ctypedef struct mbedtls_pk_context:
        pass

    mbedtls_rsa_context *mbedtls_pk_rsa(const mbedtls_pk_context pk)
    mbedtls_ecp_keypair *mbedtls_pk_ec(const mbedtls_pk_context pk)
    # RSA-alt function pointer types
    const mbedtls_pk_info_t *mbedtls_pk_info_from_type(
        mbedtls_pk_type_t pk_type)
    void mbedtls_pk_init(mbedtls_pk_context *ctx)
    void mbedtls_pk_free(mbedtls_pk_context *ctx)
    int mbedtls_pk_setup(mbedtls_pk_context *ctx,
                         const mbedtls_pk_info_t *info)

    size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx)
    size_t mbedtls_pk_get_len(const mbedtls_pk_context *ctx)
    # int mbedtls_pk_can_do(const mbedtls_pk_context *ctx,
    #                       mbedtls_pk_type_t type)

    int mbedtls_pk_verify(
        mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        const unsigned char *sig, size_t sig_len)
    # int mbedtls_pk_verify_ext(
    #     mbedtls_pk_type_t type, const void *options,
    #     mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
    #     const unsigned char *hash, size_t hash_len,
    #     const unsigned char *sig, size_t sig_len)

    int mbedtls_pk_sign(
        mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        unsigned char *sig, size_t *sig_len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_pk_decrypt(
        mbedtls_pk_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
    int mbedtls_pk_encrypt(
        mbedtls_pk_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_pk_check_pair(const mbedtls_pk_context *pub,
                              const mbedtls_pk_context *prv)
    # int mbedtls_pk_debug(const mbedtls_pk_context *ctx,
    #                      mbedtls_pk_debug_item *items)
    const char * mbedtls_pk_get_name(const mbedtls_pk_context *ctx)
    mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)

    int mbedtls_pk_parse_key(
        mbedtls_pk_context *ctx,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen)
    int mbedtls_pk_parse_public_key(
        mbedtls_pk_context *ctx,
        const unsigned char *key, size_t keylen)

    # int mbedtls_pk_parse_keyfile(
    #     mbedtls_pk_context *ctx,
    #     const char *path, const char *password)
    # int mbedtls_pk_parse_public_keyfile(
    #     mbedtls_pk_context *ctx, const char *path)

    int mbedtls_pk_write_key_der(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_pubkey_der(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_pubkey_pem(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_key_pem(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)


cdef class CipherBase:
    cdef mbedtls_pk_context _ctx

    cpdef bint has_private(self)
    cpdef bint has_public(self)

    cdef bytes _write(
        self,
        int (*fun)(mbedtls_pk_context*, unsigned char*, size_t),
        size_t)


cdef class ECPoint:
    cdef mbedtls_ecp_point _ctx


cdef class ECGroup:
    cdef mbedtls_ecp_group _ctx


cdef class ECKeyPair:
    cdef mbedtls_ecp_keypair _ctx