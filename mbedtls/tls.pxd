"""Declarations from `mbedtls/ssl.h."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef:
    enum: MBEDTLS_SSL_TRANSPORT_STREAM = 0
    enum: MBEDTLS_SSL_TRANSPORT_DATAGRAM = 1
    enum: MBEDTLS_SSL_PRESET_DEFAULT = 0
    enum: MBEDTLS_SSL_PRESET_SUITEB = 2
    enum: MBEDTLS_SSL_VERIFY_NONE = 0
    enum: MBEDTLS_SSL_VERIFY_OPTIONAL = 1
    enum: MBEDTLS_SSL_VERIFY_REQUIRED = 2


cdef extern from "mbedtls/pk.h":
    ctypedef enum mbedtls_pk_context: pass


cdef extern from "mbedtls/x509.h":
    ctypedef enum mbedtls_x509_crt: pass


cdef extern from "mbedtls/ssl.h":
    # Defined here
    # ------------
    # ctypedef enum mbedtls_ssl_states: pass
    ctypedef enum mbedtls_ssl_session: pass
    ctypedef enum mbedtls_ssl_config: pass
    ctypedef enum mbedtls_ssl_context: pass

    # Defined in ssl_internal.h
    # -------------------------
    # ctypedef enum mbedtls_ssl_transform: pass
    # ctypedef enum mbedtls_ssl_handshake_params: pass
    # ctypedef enum mbedtls_ssl_key_cert: pass

    # Callback types
    # --------------
    # mbedtls_ssl_send_t
    # mbedtls_ssl_recv_t
    # mbedtls_ssl_recv_timeout_t
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
    # mbedtls_ssl_conf_ca_chain

    int mbedtls_ssl_conf_own_cert(
        mbedtls_ssl_config *conf,
        mbedtls_x509_crt *own_cert,
        mbedtls_pk_context *pk_key)

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
    # mbedtls_ssl_conf_rng
    # mbedtls_ssl_conf_dbg
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

    # mbedtls_ssl_set_bio
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
    # const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(
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


cdef class _TLSConfiguration:
    cdef mbedtls_ssl_config _ctx
    cdef int* _ciphers


cdef class _TLSSession:
    cdef mbedtls_ssl_session _ctx


cdef class _BaseContext:
    cdef mbedtls_ssl_context _ctx
    cdef _TLSConfiguration _conf
    cpdef _reset(self)
    cpdef _read(self, size_t mt)
    cpdef _read_buffer(self, unsigned char[:] buffer, size_t amt)