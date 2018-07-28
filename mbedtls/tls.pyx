"""TLS/SSL wrapper for socket objects."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


BUFFER = False


from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cimport mbedtls.pk as _pk
cimport mbedtls._net as _net
cimport mbedtls.random as _random
cimport mbedtls.tls as _tls
cimport mbedtls.x509 as _x509

import socket as _socket
from collections import namedtuple
from enum import Enum, IntEnum
from ipaddress import ip_address

import certifi

import mbedtls.random as _random
from mbedtls import _pep543
from mbedtls.exceptions import *


cdef _random.Random __rng = _random.Random()


cdef int buffer_send(void *ctx, const unsigned char *buf, size_t len):
    assert len <= _tls.TLS_BUFFER_CAPACITY
    c_ctx = <_IOContext *>ctx
    if c_ctx.ssl.state != _tls.MBEDTLS_SSL_HANDSHAKE_OVER:
        # print("> HS[%i]\n\t%r" % (len, bytes(buf[:len])))
        return _net.mbedtls_net_send(ctx, buf, len)
    else:
        print("\n> MSG[%i]\n\t%r" % (len, bytes(buf[:len])))
        return _net.mbedtls_net_send(ctx, buf, len)


cdef int buffer_recv(void *ctx, unsigned char *buf, size_t len):
    assert len <= _tls.TLS_BUFFER_CAPACITY
    c_ctx = <_IOContext *>ctx
    if c_ctx.ssl.state != _tls.MBEDTLS_SSL_HANDSHAKE_OVER:
        # print("< HS[%i]\n\t%r" % (len, bytes(buf[:len])))
        return _net.mbedtls_net_recv(ctx, buf, len)
    else:
        print("\n< MSG[%i]\n\t%r" % (len, bytes(buf[:len])))
        return _net.mbedtls_net_recv(ctx, buf, len)


cdef void debug(
    # FIXME Is this really necessary?
        void *ctx, int level,
        const char* file, int line, const char *str):
    print(file, line, str)


def __get_ciphersuite_name(ciphersuite_id):
    """Return a string containing the ciphersuite name.

    Args:
        ciphersuite_id: The ID of the ciphersuite.

    """
    return _tls.mbedtls_ssl_get_ciphersuite_name(
        ciphersuite_id).decode("ascii")


def __get_ciphersuite_id(name):
    """Return the ciphersuite name from ID.

    Args:
        name (str): The name of the ciphersuite.

    """
    cdef char[:] c_name = bytearray(name.encode("ascii"))
    return _tls.mbedtls_ssl_get_ciphersuite_id(&c_name[0])


def ciphers_available():
    """Return the list of ciphersuites supported by the SSL/TLS module.

    See Also:
        - hash.algorithms_available
        - hmac.algorithms_available

    """
    cdef const int* ids = _tls.mbedtls_ssl_list_ciphersuites()
    cdef size_t n = 0
    ciphersuites = []
    while ids[n]:
        ciphersuites.append(__get_ciphersuite_name(ids[n]))
        n += 1
    return ciphersuites


class NextProtocol(Enum):
    # PEP 543
    H2 = b'h2'
    H2C = b'h2c'
    HTTP1 = b'http/1.1'
    WEBRTC = b'webrtc'
    C_WEBRTC = b'c-webrtc'
    FTP = b'ftp'
    STUN = b'stun.nat-discovery'
    TURN = b'stun.turn'


class TLSVersion(IntEnum):
    # PEP 543
    MINIMUM_SUPPORTED = _tls.MBEDTLS_SSL_MINOR_VERSION_0
    SSLv3 = _tls.MBEDTLS_SSL_MINOR_VERSION_0
    TLSv1 = _tls.MBEDTLS_SSL_MINOR_VERSION_1
    TLSv1_1 = _tls.MBEDTLS_SSL_MINOR_VERSION_2
    TLSv1_2 = _tls.MBEDTLS_SSL_MINOR_VERSION_3
    MAXIMUM_SUPPORTED = _tls.MBEDTLS_SSL_MINOR_VERSION_3


class HandshakeStep(IntEnum):
    HELLO_REQUEST = _tls.MBEDTLS_SSL_HELLO_REQUEST
    CLIENT_HELLO = _tls.MBEDTLS_SSL_CLIENT_HELLO
    SERVER_HELLO = _tls.MBEDTLS_SSL_SERVER_HELLO
    SERVER_CERTIFICATE = _tls.MBEDTLS_SSL_SERVER_CERTIFICATE
    SERVER_KEY_EXCHANGE = _tls.MBEDTLS_SSL_SERVER_KEY_EXCHANGE
    CERTIFICATE_REQUEST = _tls.MBEDTLS_SSL_CERTIFICATE_REQUEST
    SERVER_HELLO_DONE = _tls.MBEDTLS_SSL_SERVER_HELLO_DONE
    CLIENT_CERTIFICATE = _tls.MBEDTLS_SSL_CLIENT_CERTIFICATE
    CLIENT_KEY_EXCHANGE = _tls.MBEDTLS_SSL_CLIENT_KEY_EXCHANGE
    CERTIFICATE_VERIFY = _tls.MBEDTLS_SSL_CERTIFICATE_VERIFY
    CLIENT_CHANGE_CIPHER_SPEC = _tls.MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC
    CLIENT_FINISHED = _tls.MBEDTLS_SSL_CLIENT_FINISHED
    SERVER_CHANGE_CIPHER_SPEC = _tls.MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC
    SERVER_FINISHED = _tls.MBEDTLS_SSL_SERVER_FINISHED
    FLUSH_BUFFERS = _tls.MBEDTLS_SSL_FLUSH_BUFFERS
    HANDSHAKE_WRAPUP = _tls.MBEDTLS_SSL_HANDSHAKE_WRAPUP
    HANDSHAKE_OVER = _tls.MBEDTLS_SSL_HANDSHAKE_OVER
    SERVER_NEW_SESSION_TICKET = _tls.MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET
    SERVER_HELLO_VERIFY_REQUEST_SENT = _tls.MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT


PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


class WantWriteError(TLSError):
    pass


class WantReadError(TLSError):
    pass


class RaggedEOF(TLSError):
    pass


class TrustStore:
    def __init__(self, db=None):
        if db is None:
            db = []
        self._db = tuple(db)

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self._db)

    @classmethod
    def system(cls):
        return cls.from_pem_file(certifi.where())

    @classmethod
    def from_pem_file(cls, path):
        certs = []
        with open(str(path)) as cacert:
            inpem = False
            for line in cacert.readlines():
                if line.startswith(PEM_HEADER):
                    inpem = True
                    certs.append([])
                elif line.strip().endswith(PEM_FOOTER):
                    inpem = False
                if inpem:
                    certs[-1].append(line)
        return cls(
            tuple(_x509.Certificate.from_PEM("".join(cert)) for cert in certs))

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._db == other._db

    def __bool__(self):
        return bool(self._db)

    def __len__(self):
        return len(self._db)

    def __iter__(self):
        return iter(self._db)

    def __contains__(self, other):
        return other in self._db


class Purpose(IntEnum):
    SERVER_AUTH = _tls.MBEDTLS_SSL_IS_SERVER
    CLIENT_AUTH = _tls.MBEDTLS_SSL_IS_CLIENT


_DEFAULT_VALUE = object()


cdef class TLSConfiguration:
    """TLS configuration."""
    def __init__(
            self,
            validate_certificates=None,
            certificate_chain=None,
            ciphers=None,
            inner_protocols=None,
            lowest_supported_version=None,
            highest_supported_version=None,
            trust_store=None,
            sni_callback=None):
        check_error(_tls.mbedtls_ssl_config_defaults(
            &self._ctx,
            endpoint=0,  # XXX server / client is not known here...
            transport=_tls.MBEDTLS_SSL_TRANSPORT_STREAM,
            preset=_tls.MBEDTLS_SSL_PRESET_DEFAULT))

        # Keep the object alive.
        self._trust_store = trust_store

        self._set_validate_certificates(validate_certificates)
        self._set_certificate_chain(certificate_chain)
        self._set_ciphers(ciphers)
        self._set_inner_protocols(inner_protocols)
        self._set_lowest_supported_version(lowest_supported_version)
        self._set_highest_supported_version(highest_supported_version)
        self._set_trust_store(trust_store)
        self._set_sni_callback(sni_callback)

        # Set random engine.
        _tls.mbedtls_ssl_conf_rng(
            &self._ctx, &_random.mbedtls_ctr_drbg_random, &__rng._ctx)
        # and debug function.
        _tls.mbedtls_ssl_conf_dbg(&self._ctx, &debug, NULL)

    def __cinit__(self):
        _tls.mbedtls_ssl_config_init(&self._ctx)

        cdef int ciphers_sz = len(ciphers_available()) + 1
        self._ciphers = <int *>malloc(ciphers_sz * sizeof(int))
        if not self._ciphers:
            raise MemoryError()
        for idx in range(ciphers_sz):
            self._ciphers[idx] = 0

        cdef int protos_sz = len(NextProtocol) + 1
        self._protos = <char **>malloc(protos_sz * sizeof(char *))
        if not self._protos:
            raise MemoryError()
        for idx in range(protos_sz):
            self._protos[idx] = NULL

    def __dealloc__(self):
        _tls.mbedtls_ssl_config_free(&self._ctx)
        free(self._ciphers)
        free(self._protos)

    def __repr__(self):
        return ("%s("
                "validate_certificates=%r, "
                "certificate_chain=%r, "
                "ciphers=%r, "
                "inner_protocols=%r, "
                "lowest_supported_version=%r, "
                "highest_supported_version=%r, "
                "trust_store=%r, "
                "sni_callback=%r)"
                % (type(self).__name__,
                   self.validate_certificates,
                   self.certificate_chain,
                   self.ciphers,
                   self.inner_protocols,
                   self.lowest_supported_version,
                   self.highest_supported_version,
                   self.trust_store,
                   self.sni_callback))

    cdef _set_validate_certificates(self, validate):
        """Set the certificate verification mode.

        """  # PEP 543
        if validate is None:
            return
        _tls.mbedtls_ssl_conf_authmode(
            &self._ctx,
            _tls.MBEDTLS_SSL_VERIFY_NONE if validate is False else
            _tls.MBEDTLS_SSL_VERIFY_REQUIRED)

    @property
    def validate_certificates(self):
        return self._ctx.authmode != _tls.MBEDTLS_SSL_VERIFY_NONE

    cdef _set_certificate_chain(self, chain):
        """The certificate, intermediate certificate, and
        the corresponding private key for the leaf certificate.

        Args:
            chain (Tuple[Tuple[Certificate], PrivateKey]):
                The certificate chain.

        """  # PEP 543
        if not chain:
            return
        certs, pk_key = chain
        c_pk_key = <_pk.CipherBase?> pk_key
        for cert in certs:
            c_cert = <_x509.Certificate?> cert
            check_error(_tls.mbedtls_ssl_conf_own_cert(
                &self._ctx, &c_cert._ctx, &c_pk_key._ctx))

    @property
    def certificate_chain(self):
        # certificates chained at:
        # mbedtls_ssl_config::mbedtls_ssl_key_cert *key_cert
        #   key_cert.cert
        #   key_cert.key
        #   key_cert.next
        #
        # alt: check keys in mbedtls_x509write_cert
        chain = []
        while False:  # XXX not implemented!
            key_cert = self._ctx.key_cert
            if key_cert is NULL:
                break
            cert = key_cert.cert
            key = key_cert.key
            # Both:
            # - convert to DER (call C function)
            # - feed into X.from_DER()
        return tuple(chain)

    cdef _set_ciphers(self, ciphers):
        """The available ciphers for the TLS connections.

        Args:
            ciphers (Tuple[Union[CipherSuite, int]]): The ciphers.

        """ # PEP 543
        if ciphers is None:
            return
        if len(ciphers) > len(ciphers_available()):
            raise ValueError("invalid ciphers")
        cdef size_t idx = 0
        self._ciphers[idx] = 0
        for idx, cipher in enumerate(ciphers):
            if not isinstance(cipher, int):
                cipher = __get_ciphersuite_id(cipher)
            self._ciphers[idx] = cipher
        self._ciphers[idx + 1] = 0
        _tls.mbedtls_ssl_conf_ciphersuites(&self._ctx, self._ciphers)

    @property
    def ciphers(self):
        ciphers = []
        cdef int cipher_id
        cdef size_t idx
        for idx in range(len(ciphers_available())):
            cipher_id = self._ciphers[idx]
            if cipher_id == 0:
                break
            ciphers.append(__get_ciphersuite_name(cipher_id))
        return ciphers

    cdef _set_inner_protocols(self, protocols):
        """

        Args:
            protocols ([Tuple[Union[NextProtocol, bytes]]]): Protocols
                that connections created with this configuration should
                advertise as supported during the TLS handshake. These may
                be advertised using either or both of ALPN or NPN. This
                list of protocols should be ordered by preference.

        """
        # PEP 543
        if protocols is None:
            return
        if len(protocols) > len(NextProtocol):
            raise ValueError("invalid protocols")
        cdef size_t idx = 0
        self._protos[idx] = NULL
        for idx, proto in enumerate(protocols):
            if not isinstance(proto, bytes):
                proto = proto.value
            self._protos[idx] = proto
        self._protos[idx + 1] = NULL
        check_error(_tls.mbedtls_ssl_conf_alpn_protocols(
            &self._ctx, self._protos))

    @property
    def inner_protocols(self):
        protos = []
        cdef const char* proto
        for idx in range(len(NextProtocol)):
            proto = self._protos[idx]
            if proto is NULL:
                break
            protos.append(NextProtocol(proto))
        return tuple(protos)

    cdef _set_lowest_supported_version(self, version):
        """The minimum version of TLS that should be allowed.

        Args:
            version (TLSVersion): The minimum version.

        """  # PEP 543
        if version is None:
            return
        _tls.mbedtls_ssl_conf_min_version(
            &self._ctx,
            _tls.MBEDTLS_SSL_MAJOR_VERSION_3,
            int(version))

    @property
    def lowest_supported_version(self):
        return TLSVersion(self._ctx.min_minor_ver)

    cdef _set_highest_supported_version(self, version):
        """The maximum version of TLS that should be allowed.

        Args:
            version (TLSVersion): The maximum version.

        """  # PEP 543
        if version is None:
            return
        _tls.mbedtls_ssl_conf_max_version(
            &self._ctx,
            _tls.MBEDTLS_SSL_MAJOR_VERSION_3,
            int(version))

    @property
    def highest_supported_version(self):
        return TLSVersion(self._ctx.max_minor_ver)

    cdef _set_trust_store(self, store):
        """The trust store that connections will use.

        Args:
            store (TrustStore): The trust store.

        """ # PEP 543
        if store is None:
            return
        cdef _x509.Certificate cert = store._db[0]
        mbedtls_ssl_conf_ca_chain(&self._ctx, &cert._ctx, NULL)

    @property
    def trust_store(self):
        return self._trust_store

    cdef _set_sni_callback(self, callback):
        # PEP 543, optional, server-side only
        if callback is None:
            return
        # mbedtls_ssl_conf_sni
        raise NotImplementedError

    @property
    def sni_callback(self):
        return None

    def update(self,
               validate_certificates=_DEFAULT_VALUE,
               certificate_chain=_DEFAULT_VALUE,
               ciphers=_DEFAULT_VALUE,
               inner_protocols=_DEFAULT_VALUE,
               lowest_supported_version=_DEFAULT_VALUE,
               highest_supported_version=_DEFAULT_VALUE,
               trust_store=_DEFAULT_VALUE,
               sni_callback=_DEFAULT_VALUE):
        """Create a new ``TLSConfiguration``.

        Override some of the settings on the original configuration
        with the new settings.

        """
        if validate_certificates is _DEFAULT_VALUE:
            validate_certificates = self.validate_certificates

        if certificate_chain is _DEFAULT_VALUE:
            certificate_chain = self.certificate_chain

        if ciphers is _DEFAULT_VALUE:
            ciphers = self.ciphers

        if inner_protocols is _DEFAULT_VALUE:
            inner_protocols = self.inner_protocols

        if lowest_supported_version is _DEFAULT_VALUE:
            lowest_supported_version = self.lowest_supported_version

        if highest_supported_version is _DEFAULT_VALUE:
            highest_supported_version = self.highest_supported_version

        if trust_store is _DEFAULT_VALUE:
            trust_store = self.trust_store

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        return self.__class__(
            validate_certificates, certificate_chain, ciphers, inner_protocols,
            lowest_supported_version, highest_supported_version, trust_store,
            sni_callback)



DEFAULT_CIPHER_LIST = _pep543.DEFAULT_CIPHER_LIST  # None


cdef class _TLSSession:
    def __cinit__(self):
        """Initialize SSL session structure."""
        _tls.mbedtls_ssl_session_init(&self._ctx)

    def __dealloc__(self):
        """Free referenced items in an SSL session."""
        _tls.mbedtls_ssl_session_free(&self._ctx)


cdef class _BaseContext:
    # _pep543._BaseContext
    """Context base class.

    Args:
        configuration (TLSConfiguration): The configuration.

    """
    def __init__(self, TLSConfiguration configuration not None):
        self._conf = configuration
        check_error(_tls.mbedtls_ssl_setup(&self._ctx, &self._conf._ctx))

    def __cinit__(self):
        """Initialize an `ssl_context`."""
        _tls.mbedtls_ssl_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the internal structures of ctx."""
        _tls.mbedtls_ssl_free(&self._ctx)

    @property
    def configuration(self):
        # PEP 543
        return self._conf

    @property
    def _purpose(self):
        return Purpose(self._conf._ctx.endpoint)

    cpdef _reset(self):
        check_error(_tls.mbedtls_ssl_session_reset(&self._ctx))

    def _shutdown(self):
        self._reset()

    def _close(self):
        self._shutdown()

    def _read(self, size_t amt):
        if not amt:
            return b""
        buffer = bytearray(amt)
        amt = self._readinto(buffer, amt)
        return bytes(buffer[:amt])

    def _readinto(self, unsigned char[:] buffer, size_t amt):
        if not amt:
            return b""
        while True:
            ret = _tls.mbedtls_ssl_read(&self._ctx, &buffer[0], amt)
            if ret > 0:
                return ret
            elif ret == 0:
                raise RaggedEOF()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            elif ret == _tls.MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
                # Handle that properly.
                check_error(ret)
            else:
                self._reset()
                check_error(ret)

    def _write(self, const unsigned char[:] buffer):
        while True:
            ret = _tls.mbedtls_ssl_write(
                &self._ctx, &buffer[0], buffer.shape[0])
            if ret >= 0:
                return ret
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            else:
                self._reset()
                check_error(ret)

    # def getpeercert(self, binary_form=False):
    #     crt = _tls.mbedtls_ssl_get_peer_cert()

    def _selected_npn_protocol(self):
        return None

    def _negotiated_protocol(self):
        cdef const char* protocol = _tls.mbedtls_ssl_get_alpn_protocol(
            &self._ctx)
        if protocol is NULL:
            return None
        return protocol.decode("ascii")

    def _cipher(self):
        cdef const char* name = _tls.mbedtls_ssl_get_ciphersuite(&self._ctx)
        if name is NULL:
            return None
        ssl_version = self._negotiated_tls_version()
        secret_bits = None
        return name.decode("ascii"), ssl_version, secret_bits

    @property
    def _state(self):
        return HandshakeStep(self._ctx.state)

    def _do_handshake_step(self):
        # self._state == 16 is MBEDTLS_SSL_HANDSHAKE_OVER
        while True:
            ret = _tls.mbedtls_ssl_handshake_step(&self._ctx)
            if ret == 0:
                return self._state
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            else:
                self._reset()
                check_error(ret)

    def _do_handshake(self):
        """Start the SSL/TLS handshake."""
        while True:
            ret = _tls.mbedtls_ssl_handshake(&self._ctx)
            if ret == 0:
                return
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            else:
                assert ret < 0
                self._reset()
                check_error(ret)

    def _renegotiate(self):
        """Initialize an SSL renegotiation on the running connection."""
        while True:
            ret = _tls.mbedtls_ssl_renegotiate(&self._ctx)
            if ret == 0:
                return
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            else:
                assert ret < 0
                self._reset()
                check_error(ret)

    def _get_channel_binding(self, cb_type="tls-unique"):
        return None

    def _negotiated_tls_version(self):
        # Strings from `ssl_tls.c`.
        # DTLS:
        #   "DTLSv1.0"
        #   "DTLSv1.2"
        #   "unknown (DTLS)"
        return {
            "SSLv3.0": TLSVersion.SSLv3,
            "TLSv1.0": TLSVersion.TLSv1,
            "TLSv1.1": TLSVersion.TLSv1_1,
            "TLSv1.2": TLSVersion.TLSv1_2,
        }.get(_tls.mbedtls_ssl_get_version(&self._ctx).decode("ascii"),
              "unknown")


cdef class ClientContext(_BaseContext):
    # _pep543.ClientContext

    def __init__(self, TLSConfiguration configuration not None):
        _tls.mbedtls_ssl_conf_endpoint(
            &configuration._ctx, _tls.MBEDTLS_SSL_IS_CLIENT)
        super(ClientContext, self).__init__(configuration)

    def wrap_socket(self, socket, server_hostname):
        """Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        Args:
            socket (socket.socket): The socket to wrap.
            server_hostname (str, optional): The hostname of the service
                which we are connecting to.  Pass ``None`` if hostname
                validation is not desired.  This parameter has no
                default value because opting-out hostname validation is
                dangerous and should not be the default behavior.

        """
        input, output = self.wrap_buffers(server_hostname)
        return TLSWrappedSocket(socket, input, output)

    def wrap_buffers(self, server_hostname=None):
        """Create an in-memory stream for TLS."""
        # PEP 543
        if server_hostname is not None:
            self.set_hostname(server_hostname)
        return TLSWrappedBuffer(self), TLSWrappedBuffer(self)

    def set_hostname(self, hostname):
        """Set the hostname to check against the received server."""
        if hostname is None:
            return
        # Note: `ssl_set_hostname()` makes a copy so it is safe
        #       to call with the temporary `hostname_`.
        hostname_ = hostname.encode("utf8")
        cdef const char* c_hostname = hostname_
        check_error(_tls.mbedtls_ssl_set_hostname(&self._ctx, c_hostname))

    def save_session(self):
        """Save session in order to resume it."""
        cdef _TLSSession session = _TLSSession()
        check_error(_tls.mbedtls_ssl_get_session(&self._ctx, &session._ctx))
        return session

    def resume_session(self, _TLSSession session):
        """Request resumption of session."""
        check_error(_tls.mbedtls_ssl_set_session(&self._ctx, &session._ctx))


cdef class ServerContext(_BaseContext):
    # _pep543.ServerContext

    def __init__(self, TLSConfiguration configuration not None):
        _tls.mbedtls_ssl_conf_endpoint(
            &configuration._ctx, _tls.MBEDTLS_SSL_IS_SERVER)
        super(ServerContext, self).__init__(configuration)

    def wrap_socket(self, socket):
        """Wrap an existing Python socket object ``socket``."""
        input, output = self.wrap_buffers()
        return TLSWrappedSocket(socket, input, output)

    def wrap_buffers(self):
        # PEP 543
        return TLSWrappedBuffer(self), TLSWrappedBuffer(self)


cdef class TLSWrappedBuffer:
    # _pep543.TLSWrappedBuffer
    def __init__(self, _BaseContext context):
        self._context = context

    def __cinit__(self):
        self._buffer.len = 0
        self._buffer.buf = <unsigned char *>malloc(
            _tls.TLS_BUFFER_CAPACITY * sizeof(unsigned char))
        if not self._buffer.buf:
            raise MemoryError()

    def __dealloc__(self):
        # XXX Use PyBuffer!
        free(self._buffer.buf)
        self._buffer.len = 0

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.context)

    def __bytes__(self):
        return bytes(self._buffer.buf[self._buffer.len])

    def read(self, size_t amt):
        # PEP 543
        return self.context._read(amt)

    def readinto(self, unsigned char[:] buffer, size_t amt):
        # PEP 543
        return self.context._readinto(buffer, amt)

    def write(self, const unsigned char[:] buf):
        # PEP 543
        return self.context._write(buf)

    def do_handshake(self):
        # PEP 543
        self.context._do_handshake()

    def cipher(self):
        # PEP 543
        cipher = self.context._cipher()
        if cipher is None:
            return cipher
        else:
            return cipher[0]

    def negotiated_protocol(self):
        # PEP 543
        return self.context._negotiated_protocol()

    @property
    def context(self):
        # PEP 543
        """The ``Context`` object this buffer is tied to."""
        return self._context

    def negotiated_tls_version(self):
        # PEP 543
        return self.context._negotiated_tls_version()

    def shutdown(self):
        # PEP 543
        self._context._shutdown()

    def receive_from_network(self, const unsigned char[:] data not None):
        # PEP 543
        # Append to data to input buffer.
        # XXX Ring buffer...
        assert data.size
        if self._buffer.len + data.size > _tls.TLS_BUFFER_CAPACITY:
            raise BufferError("Input buffer overflow")

        cdef size_t end = self._buffer.len * sizeof(unsigned char)
        memcpy(&self._buffer.buf[end], &data[0], data.size)

    def peek_outgoing(self, size_t amt):
        # PEP 543
        # Read from output buffer.
        return bytes(self)[:amt]

    def consume_outgoing(self, size_t amt):
        # PEP 543
        # Remove up to `amt` from `output`.
        # XXX Ring buffer... -> move begin by `amt`
        self._buffer.len = amt


cdef class TLSWrappedSocket:
    # _pep543.TLSWrappedSocket
    def __init__(self,
                 socket,
                 TLSWrappedBuffer input,
                 TLSWrappedBuffer output):
        super().__init__()
        self._socket = socket
        self._input = input
        self._output = output
        self._proto = _net.MBEDTLS_NET_PROTO_TCP
        if socket is not None and socket.fileno() != -1:
            # Implementation detail.
            self._ctx.fd = socket.fileno()

    def __cinit__(self,
                  socket,
                  TLSWrappedBuffer input,
                  TLSWrappedBuffer output):
        _net.mbedtls_net_init(<_net.mbedtls_net_context *>&self._ctx)
        self._ctx.input = &input._buffer
        self._ctx.output = &output._buffer
        self._ctx.ssl = &input._context._ctx

    def __dealloc__(self):
        _net.mbedtls_net_free(<_net.mbedtls_net_context *>&self._ctx)
        self._ctx.input = NULL
        self._ctx.output = NULL
        self._ctx.ssl = NULL

    def __str__(self):
        return str(self._socket)

    cdef void _net_bio(self):
        _tls.mbedtls_ssl_set_bio(
            self._ctx.ssl,
            &self._ctx,
            buffer_send,
            buffer_recv,
            NULL)

    # PEP 543 requires the full socket API.

    @property
    def family(self):
        return self._socket.family

    @property
    def proto(self):
        return self._socket.proto

    @property
    def type(self):
        return self._socket.type

    def accept(self):
        input, output = ServerContext(
            self.context.configuration).wrap_buffers()
        cdef TLSWrappedSocket cli = TLSWrappedSocket(None, input, output)
        cdef size_t sz = 256
        cdef size_t ip_sz
        cdef char* buffer = <char*>malloc(sz * sizeof(char))
        if not buffer:
            raise MemoryError()
        try:
            check_error(_net.mbedtls_net_accept(
                <_net.mbedtls_net_context *>&self._ctx,
                <_net.mbedtls_net_context *>&cli._ctx,
                &buffer[0], sz, &ip_sz))
                # XXX Example has NULL, 0, NULL for the server.
                # &self._ctx, &cli._ctx, NULL, 0, NULL))
            cli._socket = _socket.socket(
                family=_socket.AF_INET,
                type={
                    _net.MBEDTLS_NET_PROTO_TCP: _socket.SOCK_STREAM,
                    _net.MBEDTLS_NET_PROTO_UDP: _socket.SOCK_DGRAM
                }[self._proto],
                # XXX Next argument is not in Python 2.7!
                fileno=cli._ctx.fd,
            )
            assert cli._socket.fileno() == cli._ctx.fd
            return cli, ip_address(bytes(buffer[:ip_sz]))
        finally:
            free(buffer)

    def bind(self, address):
        host, port = address
        port = str(port).encode("ascii")
        if host is None:
            check_error(_net.mbedtls_net_bind(
                <_net.mbedtls_net_context *>&self._ctx,
                NULL, port, self._proto))
        else:
            host = host.encode("ascii")
            check_error(_net.mbedtls_net_bind(
                <_net.mbedtls_net_context *>&self._ctx,
                host, port, self._proto))

    def close(self):
        self.context._close()
        self._socket.close()

    def connect(self, address):
        host, port = address
        port = str(port).encode("ascii")
        if host is None:
            check_error(_net.mbedtls_net_connect(
                <_net.mbedtls_net_context *>&self._ctx,
                NULL, port, self._proto))
        else:
            host = host.encode("ascii")
            check_error(_net.mbedtls_net_connect(
                <_net.mbedtls_net_context *>&self._ctx,
                host, port, self._proto))

    def connect_ex(self, address):
        self._socket.connect_ex(address)

    def fileno(self):
        return self._socket.fileno()

    def getpeername(self):
        return self._socket.getpeername()

    def getsockname(self):
        return self._socket.getsockname()

    def getsockopt(self, optname, buflen=None):
        return self._socket.getsockopt(optname, buflen=buflen)

    def listen(self, backlog):
        self._socket.listen(backlog)

    # makefile

    def recv(self, size_t bufsize, flags=0):
        # XXX Handle timeout?
        if not BUFFER:
            print("\n< RECV")
            _ = self.context._read(bufsize)
            print("\n< /RECV")
            return _
        else:
            data = self._socket.recv(bufsize, flags)
            self._input.receive_from_network(data)
            # XXX Crypted and encrypted may not have the same size.
            # XXX It is possible that we need to buffer more from
            # XXX the network than `bufsize`.
            return self._input.read(bufsize)

    def recvfrom(self, bufsize, flags=0):
        ...

    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        ...

    def recv_into(self, buffer, nbytes=None, flags=0):
        ...

    def send(self, const unsigned char[:] message, flags=0):
        if not BUFFER:
            print("\n> SEND")
            _ = self._output.write(message)
            print("\n> /SEND")
            return _
        else:
            amt = self._output.write(message)
            amt = self._socket.send(self._output.peek_outgoing(amt), flags)
            self._buffer.consume_outgoing(amt)
            return amt

    def sendall(self, string, flags=0):
        ...

    def sendto(self, string, address):
        ...

    def sendto(self, string, flags, address):
        ...

    def setblocking(self, flag):
        self._socket.setblocking(flag)

    def settimeout(self, value):
        self._socket.settimeout(value)

    def gettimeout(self):
        return self._socket.gettimeout()

    def setsockopt(self, level, optname, value):
        self._socket.setsockopt(level, optname, value)

    def shutdown(self, how):
        self.context.shutdown()
        self._socket.shutdown(how)

    # PEP 543 adds the following methods.

    def do_handshake(self):
        self._net_bio()
        self.context._do_handshake()

    def cipher(self):
        return self.context._cipher()

    def negotiated_protocol(self):
        return self.context._negotiated_protocol()

    @property
    def context(self):
        return self._input.context

    def negotiated_tls_version(self):
        return self.context._negotiated_tls_version()

    def unwrap(self):
        self.shutdown(_socket.SHUT_RDWR)
        return self._socket
