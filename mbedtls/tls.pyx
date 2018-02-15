"""TLS/SSL wrapper for socket objects."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport tls as _tls
cimport x509 as _x509
cimport mbedtls.pk._pk as _pk
from libc.stdlib cimport malloc, free

from collections import namedtuple
from enum import Enum, IntEnum
from socket import socket

import certifi

from mbedtls import _pep543
from mbedtls.exceptions import *


def __get_ciphersuite_name(ciphersuite_id):
    """Return a string containing the ciphersuite name.

    Args:
        ciphersuite_id: The ID of the ciphersuite.

    """
    return bytes(_tls.mbedtls_ssl_get_ciphersuite_name).decode("ascii")


def __get_ciphersuite_id(name):
    """Return the ciphersuite name from ID.

    Args:
        name (str): The name of the ciphersuite.

    """
    cdef char[:] c_name = bytearray(name.encode("ascii"))
    return _tls.mbedtls_ssl_get_ciphersuite_id(&c_name[0])


def __get_supported_ciphersuites():
    """Return the list of ciphersuites supported by the SSL/TLS module.

    See Also:
        mbedtls._md.__get_supported_mds()

    """
    cdef const int* ids = _tls.mbedtls_ssl_list_ciphersuites()
    cdef size_t n = 0
    ciphersuites = []
    while ids[n]:
        ciphersuites.append(__get_ciphersuite_name(ids[n]))
        n += 1
    return ciphersuites


class TLSVersion(IntEnum):
    # PEP 543
    # MBEDTLS_SSL_MINOR_VERSION_X
    MINIMUM_SUPPORTED = 0
    SSLv3 = 0
    TLSv1 = 1
    TLSv1_1 = 2
    TLSv1_2 = 3
    MAXIMUM_SUPPORTED = 3


class TrustStore(_pep543.TrustStore):
    @classmethod
    def system(cls):
        return cls.from_pem_file(certifi.where())

    @classmethod
    def from_pem_file(cls, path):
        pass


class Purpose(Enum):
    SERVER_AUTH = 0
    CLIENT_AUTH = 1


cdef class _TLSConfiguration:
    """TLS configuration.

    Args:
        server_side (bool): True for server-side socket.
        transport (int): {MBEDTLS_SSL_TRANSPORT_STREAM,
                          MBEDTLS_SSL_TRANSPORT_DATAGRAM} for TLS or DTS, resp.
        preset (int): A MBEDTLS_SSL_PRESET, default is
            MBEDTLS_SSL_PRESET_DEFAULT

    """
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
        self.set_validate_certificates(validate_certificates)
        self.set_certificate_chain(certificate_chain)
        self.set_ciphers(ciphers)
        self.set_inner_protocols(inner_protocols)
        self.set_lowest_supported_version(lowest_supported_version)
        self.set_highest_supported_version(highest_supported_version)
        self.set_trust_store(trust_store)
        self.set_sni_callback(sni_callback)

    def __cinit__(self):
        _tls.mbedtls_ssl_config_init(&self._ctx)

    def __dealloc__(self):
        _tls.mbedtls_ssl_config_free(&self._ctx)
        free(self._ciphers)

    @classmethod
    def _create_default_context(cls, purpose=Purpose.SERVER_AUTH,
                                cafile=None, capath=None, cadata=None):
        """Create a default context.

        Args:
            purpose (Purpose): SERVER_AUTH or CLIENT_AUTH

        """
        # XXX This is a free function in the std lib `ssl`.
        if not isinstance(purpose, Purpose):
            raise TypeError(purpose)
        # TLS / DTLS
        cdef int transport = _tls.MBEDTLS_SSL_TRANSPORT_STREAM
        cdef _TLSConfiguration self = cls()
        check_error(_tls.mbedtls_ssl_config_defaults(
            &self._ctx,
            1 if purpose is Purpose.SERVER_AUTH else 0,
            transport,
            0))

    def set_validate_certificates(self, validate):
        """Set the certificate verification mode.

        """  # PEP 543
        if validate is None:
            return
        _tls.mbedtls_ssl_conf_authmode(
            &self._ctx,
            _tls.MBEDTLS_SSL_VERIFY_NONE if validate is False else
            _tls.MBEDTLS_SSL_VERIFY_REQUIRED)

    def set_certificate_chain(self, chain):
        """The certificate, intermediate certificate, and
        the corresponding private key for the leaf certificate.

        Args:
            chain (Tuple[Tuple[Certificate], PrivateKey]):
                The certificate chain.

        """  # PEP 543
        if chain is None:
            return
        for certs, pk_key in chain:
            c_pk_key = <_pk.CipherBase?> pk_key
            for cert in certs:
                c_cert = <_x509.Certificate?> cert
                check_error(_tls.mbedtls_ssl_conf_own_cert(
                    &self._ctx, &c_cert._ctx, &c_pk_key._ctx))

    def set_ciphers(self, ciphers):
        """The available ciphers for the TLS connections.

        Args:
            ciphers (Tuple[Union[CipherSuite, int]]): The ciphers.

        """ # PEP 543
        if ciphers is None:
            return
        if ciphers:
            raise MemoryError("ciphers already set")
        self._ciphers = <int*>malloc(len(ciphers) * sizeof(int))
        if not self._ciphers:
            raise MemoryError
        for index, cipher in enumerate(ciphers):
            if not isinstance(cipher, int):
                cipher = __get_ciphersuite_id(cipher)
            self._ciphers[index] = cipher
        _tls.mbedtls_ssl_conf_ciphersuites(&self._ctx, &self._ciphers[0])

    def set_inner_protocols(self, protocols):
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
        # XXX mbedtls_ssl_conf_alpn_protocols
        ...

    def set_lowest_supported_version(self, version):
        """The minimum version of TLS that should be allowed.

        Args:
            version (TLSVersion): The minimum version.

        """  # PEP 543
        if version is None:
            return
        cdef int major = 3
        _tls.mbedtls_ssl_conf_min_version(
            &self._ctx, major, int(version))

    def set_highest_supported_version(self, version):
        """The maximum version of TLS that should be allowed.

        Args:
            version (TLSVersion): The maximum version.

        """  # PEP 543
        if version is None:
            return
        cdef int major = 3
        _tls.mbedtls_ssl_conf_max_version(
            &self._ctx, major, int(version))

    def set_trust_store(self, store):
        """The trust store that connections will use.

        Args:
            store (TrustStore): The trust store.

        """ # PEP 543
        if store is None:
            return
        if not isinstance(store, TrustStore):
            raise TypeError(store)
        ...

    def set_sni_callback(self, callback):
        # PEP 543, optional, server-side only
        if callback is None:
            return
        # XXX mbedtls_ssl_conf_sni
        raise NotImplementedError


DEFAULT_CIPHER_LIST = _pep543.DEFAULT_CIPHER_LIST  # None


class TLSConfiguration(
    namedtuple("TLSConfiguration",
               _pep543.TLSConfiguration._fields + ("impl", ))):
    __slots__ = ()

    def __new__(cls,
                validate_certificates=None,
                certificate_chain=None,
                ciphers=None,
                inner_protocols=None,
                lowest_supported_version=None,
                highest_supported_version=None,
                trust_store=None,
                sni_callback=None):

        if validate_certificates is None:
            validate_certificates = False

        if ciphers is None:
            ciphers = DEFAULT_CIPHER_LIST

        if inner_protocols is None:
            inner_protocols = []

        if lowest_supported_version is None:
            lowest_supported_version = TLSVersion.TLSv1

        if highest_supported_version is None:
            highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

        impl = _TLSConfiguration(True, _tls.MBEDTLS_SSL_TRANSPORT_STREAM)
        impl.validate_certificates

        return super().__new__(
            cls, validate_certificates, certificate_chain, ciphers,
            inner_protocols, lowest_supported_version,
            highest_supported_version, trust_store, sni_callback, impl)


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

    def __init__(self, _TLSConfiguration configuration):
        # PEP 543
        self._conf = configuration
        check_error(_tls.mbedtls_ssl_setup(
            &self._ctx, &configuration._ctx))
        # 0 if successful, or MBEDTLS_ERR_SSL_ALLOC_FAILED

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

    cpdef _reset(self):
        check_error(_tls.mbedtls_ssl_session_reset(&self._ctx))

    cpdef _read(self, size_t amt):
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            ret = _tls.mbedtls_ssl_read(
                &self._ctx, &output[0], output.shape[0])
            # Handle MBEDTLS_ERR_SSL_WANT_READ/WRITE
            # Handle MBEDTLS_ERR_SSL_CLIENT_RECONNECT
            if ret < 0:
                # self.close()
                self._reset()
                check_error(ret)
            else:
                if ret == 0:
                    # Handle ragged EOF
                    raise ValueError  # Raise proper exception!
                return bytes(output[:amt])
        finally:
            free(output)

    cpdef _read_buffer(self, unsigned char[:] buffer, size_t amt):
        ret = _tls.mbedtls_ssl_read(
            &self._ctx, &buffer[0], buffer.shape[0])
        # Handle MBEDTLS_ERR_SSL_WANT_READ/WRITE
        # Handle MBEDTLS_ERR_SSL_CLIENT_RECONNECT
        if ret < 0:
            # self.close()
            self._reset()
            check_error(ret)
        else:
            if ret == 0:
                # EOF
                ret = amt
            return ret

    def read(self, buffer, amt=None):
        if amt:
            return self._read_buffer(buffer, amt)
        amt = buffer
        return self._read(amt)

    def write(self, buffer):
        cdef unsigned char[:] buf = bytearray(buffer)
        if buf.shape[0] > _tls.mbedtls_ssl_get_max_frag_len(&self._ctx):
            raise ValueError  # FIXME: MBEDTLS_ERR_SSL_BAD_INPUT_DATA
        ret = _tls.mbedtls_ssl_write(
            &self._ctx, &buf[0], buf.shape[0])
        # Handle MBEDTLS_ERR_SSL_WANT_READ/WRITE
        # -> call again with the *same* arguments.
        if ret >= 0:
            return ret
        # self.close()
        self._reset()
        check_error(ret)

    # def getpeercert(self, binary_form=False):
    #     crt = _tls.mbedtls_ssl_get_peer_cert()

    def selected_npn_protocol(self):
        return None

    def selected_alpn_protocol(self):
        cdef char* protocol = _tls.mbedtls_ssl_get_alpn_protocol(&self._ctx)
        if protocol is NULL:
            return None
        return protocol.decode("ascii")

    def cipher(self):
        name = _tls.mbedtls_ssl_get_ciphersuite(&self._ctx).decode("ascii")
        ssl_version = self.version()
        secret_bits = None
        return name, ssl_version, secret_bits

    def do_handshake(self):
        """Start the SSL/TLS handshake."""
        cdef int err = _tls.mbedtls_ssl_handshake(&self._ctx)
        if err:
            self._reset()
        check_error(err)

    def renegotiate(self):
        """Initialize an SSL renegotiation on the running connection."""
        check_error(_tls.mbedtls_ssl_renegotiate(&self._ctx))
        # Handle WANT_READ/WRITE

    def get_channel_binding(self, cb_type="tls-unique"):
        return None

    def version(self):
        return _tls.mbedtls_ssl_get_version(&self._ctx).decode("ascii")


cdef class ClientContext(_tls._BaseContext):
    # _pep543.ClientContext

    def wrap_buffer(self, server_hostname=None):
        # PEP 543
        # XXX return TLSWrappedBuffer
        ...

    def set_hostname(self, hostname):
        """Set the hostname to check against the received server."""
        cdef char[:] c_hostname = hostname.encode("utf8")
        check_error(_tls.mbedtls_ssl_set_hostname(&self._ctx, &c_hostname[0]))

    def save_session(self):
        """Save session in order to resume it."""
        cdef _TLSSession session = _TLSSession()
        check_error(_tls.mbedtls_ssl_get_session(&self._ctx, &session._ctx))
        return session

    def resume_session(self, _TLSSession session):
        """Request resumption of session."""
        check_error(_tls.mbedtls_ssl_set_session(&self._ctx, &session._ctx))


cdef class ServerContext(_tls._BaseContext):
    # _pep543.ServerContext

    def wrap_buffer(self):
        # PEP 543
        # XXX return TLSWrappedBuffer
        ...


class TLSWrappedBuffer(_pep543.TLSWrappedBuffer):
    def read(self, amt):
        return self.context.read(amt)

    def readinto(self, buffer, amt):
        return self.context.read(buffer, amt)

    def write(self, buf):
        self.context.write(buf)

    def do_handshake(self):
        self.context.do_handshake()

    def cipher(self):
        ...

    def negotiated_protocol(self):
        ...

    @property
    def context(self):
        """The ``Context`` object this buffer is tied to."""
        return self._context

    def negotiated_tls_version(self):
        ...

    def shutdown(self):
        ...

    def receive_from_network(self, data):
        ...

    def peek_outgoing(self, amt):
        ...

    def consume_outgoing(self, amt):
        ...


class TLSWrappedSocket(_pep543.TLSWrappedSocket):
    # PEP 543: Full socket.socket API + following methods:

    def do_handshake(self):
        self.context.do_handshake()

    def cipher(self):
        ...

    def negotiated_protocol(self):
        ...

    @property
    def context(self):
        return self._context

    def negotiated_tls_version(self):
        ...

    def unwrap(self):
        ...
