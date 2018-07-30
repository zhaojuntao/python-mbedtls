"""Declarations from `mbedtls/ssl.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls._net as _net
cimport mbedtls.pk as _pk
cimport mbedtls.x509 as _x509


cdef:
    enum: MBEDTLS_SSL_TRANSPORT_STREAM = 0
    enum: MBEDTLS_SSL_TRANSPORT_DATAGRAM = 1
    enum: MBEDTLS_SSL_PRESET_DEFAULT = 0
    enum: MBEDTLS_SSL_PRESET_SUITEB = 2
    enum: MBEDTLS_SSL_VERIFY_NONE = 0
    enum: MBEDTLS_SSL_VERIFY_OPTIONAL = 1
    enum: MBEDTLS_SSL_VERIFY_REQUIRED = 2

    enum: MBEDTLS_SSL_MAJOR_VERSION_3 = 3
    enum: MBEDTLS_SSL_MINOR_VERSION_0 = 0
    enum: MBEDTLS_SSL_MINOR_VERSION_1 = 1
    enum: MBEDTLS_SSL_MINOR_VERSION_2 = 2
    enum: MBEDTLS_SSL_MINOR_VERSION_3 = 3

    enum: MBEDTLS_SSL_IS_CLIENT = 0
    enum: MBEDTLS_SSL_IS_SERVER = 1

    enum: MBEDTLS_ERR_SSL_WANT_READ = -0x6900
    enum: MBEDTLS_ERR_SSL_WANT_WRITE = -0x6880


cdef extern from "mbedtls/ssl_internal.h":
    ctypedef struct mbedtls_ssl_transform:
        pass

    ctypedef struct mbedtls_ssl_handshake_params:
        int sig_alg
        int verify_sig_alg
        # Diffie-Hellman key exchange:
        # mbedtls_dhm_context dhm_ctx
        _pk.mbedtls_ecdh_context ecdh_ctx
        # EC-J-Pake (not very much used anymore)
        # mbedtls_ecjpake_context ecjpake_ctx
        mbedtls_ssl_key_cert *key_cert

    ctypedef struct mbedtls_ssl_key_cert:
        _x509.mbedtls_x509_crt *cert
        _pk.mbedtls_pk_context *key
        mbedtls_ssl_key_cert *next


cdef extern from "mbedtls/ssl.h":
    # Defined here
    # ------------
    # ctypedef enum mbedtls_ssl_states: pass

    ctypedef struct mbedtls_ssl_session:
        pass

    ctypedef struct mbedtls_ssl_config:
        # set_validate_certificates
        unsigned int authmode
        # set_certificate_chain
        mbedtls_ssl_key_cert *key_cert
        # set_ciphers
        const int *ciphersuite_list[4]
        # set_inner_protocols
        const char **alpn_list
        # set_lowest_supported_version/set_highest_supported_version
        unsigned char max_major_ver
        unsigned char max_minor_ver
        unsigned char min_major_ver
        unsigned char min_minor_ver
        # set_trust_store
        # ca_chain / ca_crl
        # set_sni_callback
        # f_sni / p_sni

    ctypedef struct mbedtls_ssl_context:
        const mbedtls_ssl_config *conf

    # Callback types
    # --------------
    ctypedef int(*mbedtls_ssl_send_p)(void*, const unsigned char*, size_t)
    ctypedef int(*mbedtls_ssl_recv_p)(void*, unsigned char*, size_t)
    ctypedef int(*mbedtls_ssl_recv_timeout_p)(
        void*, unsigned char* size_t, int)

    # mbedtls_ssl_set_timer_t
    # mbedtls_ssl_get_timer_t
    # mbedtls_ssl_cookie_write_t
    # mbedtls_ssl_cookie_check_t
    # mbedtls_ssl_ticket_write_t
    # mbedtls_ssl_ticket_parse_t
    # mbedtls_ssl_export_keys_t

    # Free functions
    # --------------
    const int* mbedtls_ssl_list_ciphersuites()
    const char* mbedtls_ssl_get_ciphersuite_name(const int ciphersuite_id)
    int mbedtls_ssl_get_ciphersuite_id(const char *ciphersuite_name)

    # mbedtls_ssl_config
    # ------------------
    # mbedtls_ssl_conf_endpoint
    # mbedtls_ssl_conf_transport

    void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode)
    void mbedtls_ssl_conf_ciphersuites(
        mbedtls_ssl_config *conf,
        const int* ciphersuites)

    # mbedtls_ssl_conf_dtls_anti_replay
    # mbedtls_ssl_conf_dtls_badmac_limit
    # mbedtls_ssl_conf_handshake_timeout
    # mbedtls_ssl_conf_ciphersuites_for_version
    # mbedtls_ssl_conf_cert_profile

    void mbedtls_ssl_conf_ca_chain(
        mbedtls_ssl_config *conf,
        _x509.mbedtls_x509_crt *ca_chain,
        _x509.mbedtls_x509_crl *ca_crl)
    int mbedtls_ssl_conf_own_cert(
        mbedtls_ssl_config *conf,
        _x509.mbedtls_x509_crt *own_cert,
        _pk.mbedtls_pk_context *pk_key)

    # mbedtls_ssl_conf_psk
    # mbedtls_ssl_conf_dh_param
    # mbedtls_ssl_conf_dh_param_ctx
    # mbedtls_ssl_conf_dhm_min_bitlen
    # mbedtls_ssl_conf_curves
    # mbedtls_ssl_conf_sig_hashes
    int mbedtls_ssl_conf_alpn_protocols(
        mbedtls_ssl_config *conf,
        const char **protos)
    void mbedtls_ssl_config_init(mbedtls_ssl_config *conf)
    int mbedtls_ssl_config_defaults(
        mbedtls_ssl_config *conf,
        int endpoint,
        int transport,
        int preset)
    void mbedtls_ssl_config_free(mbedtls_ssl_config *conf)

    # mbedtls_ssl_config: set callbacks
    # ---------------------------------
    # mbedtls_ssl_conf_verify  // optional

    void mbedtls_ssl_conf_rng(
        mbedtls_ssl_config *conf,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
    void mbedtls_ssl_conf_dbg(
        mbedtls_ssl_config *conf,
        void (*f_dbg)(void *, int, const char *, int, const char *),
        void  *p_dbg )

    # mbedtls_ssl_conf_read_timeout
    # mbedtls_ssl_conf_session_tickets_cb
    # mbedtls_ssl_conf_export_keys_cb
    # mbedtls_ssl_conf_dtls_cookies
    # mbedtls_ssl_conf_session_cache
    # mbedtls_ssl_conf_psk_cb
    void mbedtls_ssl_conf_sni(
        mbedtls_ssl_config *conf,
        int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char*,
                     size_t),
        void* p_sni)
    void mbedtls_ssl_conf_max_version(
        mbedtls_ssl_config *conf,
        int major,
        int minor)
    void mbedtls_ssl_conf_min_version(
        mbedtls_ssl_config *conf,
        int major,
        int minor)
    # mbedtls_ssl_conf_fallback
    # mbedtls_ssl_conf_encrypt_then_mac
    # mbedtls_ssl_conf_extended_master_secret
    # mbedtls_ssl_conf_arc4_support
    # mbedtls_ssl_conf_max_frag_len
    # mbedtls_ssl_conf_truncated_hmac
    # mbedtls_ssl_conf_cbc_record_splitting
    # mbedtls_ssl_conf_session_tickets
    # mbedtls_ssl_conf_renegotiation
    # mbedtls_ssl_conf_legacy_renegotiation
    # mbedtls_ssl_conf_renegotiation_enforced
    # mbedtls_ssl_conf_renegotiation_period

    # mbedtls_ssl_context
    # -------------------
    void mbedtls_ssl_init(mbedtls_ssl_context *ctx)
    int mbedtls_ssl_setup(
        mbedtls_ssl_context *ctx,
        const mbedtls_ssl_config *conf)
    int mbedtls_ssl_session_reset(mbedtls_ssl_context *ctx)
    void mbedtls_ssl_set_bio(
        mbedtls_ssl_context *ssl,
        void *p_bio,
        mbedtls_ssl_send_p f_send,
        mbedtls_ssl_recv_p f_recv,
        mbedtls_ssl_recv_timeout_p f_recv_timeout)

    # mbedtls_ssl_set_timer_cb
    # mbedtls_ssl_set_client_transport_id
    int mbedtls_ssl_set_session(
        const mbedtls_ssl_context *ssl,
        mbedtls_ssl_session *session)
    # mbedtls_ssl_set_hs_psk
    int mbedtls_ssl_set_hostname(
        mbedtls_ssl_context *ssl,
        const char *hostname)
    # mbedtls_ssl_set_hs_ecjpake_password
    # mbedtls_ssl_set_hs_own_cert
    # mbedtls_ssl_set_hs_ca_chain
    # mbedtls_ssl_set_hs_authmode
    const char* mbedtls_ssl_get_alpn_protocol(const mbedtls_ssl_context *ctx)
    # mbedtls_ssl_get_bytes_avail
    # mbedtls_ssl_get_verify_result
    const char* mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl)
    const char* mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl)
    # mbedtls_ssl_get_record_expansion
    size_t mbedtls_ssl_get_max_frag_len(const mbedtls_ssl_context *ssl)
    # const _x509.mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(
    #     const mbedtls_ssl_context *ctx)
    int mbedtls_ssl_get_session(
        const mbedtls_ssl_context *ssl,
        mbedtls_ssl_session *session)
    int mbedtls_ssl_handshake(mbedtls_ssl_context *ctx)
    # mbedtls_ssl_handshake_step
    int mbedtls_ssl_renegotiate(mbedtls_ssl_context *ssl)
    int mbedtls_ssl_read(
        mbedtls_ssl_context *ctx,
        unsigned char *buf,
        size_t len)
    int mbedtls_ssl_write(
        mbedtls_ssl_context *ctx,
        const unsigned char *buf,
        size_t len)
    # mbedtls_ssl_send_alert_message
    # mbedtls_ssl_close_notify
    void mbedtls_ssl_free(mbedtls_ssl_context *ctx)

    # mbedtls_ssl_session
    # -------------------
    void mbedtls_ssl_session_init(mbedtls_ssl_session *session)
    void mbedtls_ssl_session_free(mbedtls_ssl_session *session)


cdef class TLSConfiguration:
    cdef mbedtls_ssl_config _ctx
    cdef int *_ciphers
    cdef char **_protos
    cdef object _trust_store
    # cdef'd because we aim at a non-writable structure.
    cdef _set_validate_certificates(self, validate)
    cdef _set_certificate_chain(self, chain)
    cdef _set_ciphers(self, ciphers)
    cdef _set_inner_protocols(self, protocols)
    cdef _set_lowest_supported_version(self, version)
    cdef _set_highest_supported_version(self, version)
    cdef _set_trust_store(self, object store)
    cdef _set_sni_callback(self, callback)


cdef class _TLSSession:
    cdef mbedtls_ssl_session _ctx


cdef class _BaseContext:
    cdef mbedtls_ssl_context _ctx
    cdef TLSConfiguration _conf
    cpdef _reset(self)
    cpdef _read(self, size_t mt)
    cpdef _read_buffer(self, unsigned char[:] buffer, size_t amt)


cdef class TLSWrappedBuffer:
    cdef _BaseContext _context


cdef class TLSWrappedSocket:
    cdef _net.mbedtls_net_context _ctx
    cdef TLSWrappedBuffer _buffer
    cdef int _proto
    cdef _socket
