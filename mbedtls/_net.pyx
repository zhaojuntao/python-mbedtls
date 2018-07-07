"""Net socket wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls._net as _net


cdef class Socket:
    def __init__(self):
        self._proto = _net.MBEDTLS_NET_PROTO_TCP

    def __cinit__(self):
        _net.mbedtls_net_init(&self._ctx)

    def __dealloc__(self):
        _net.mbedtls_net_free(&self._ctx)

    def connect(self, address):
        host, port = address
        check_error(mbedtls_net_connect(
            &self._ctx, host.encode("ascii"), str(port).encode("ascii"),
            self._proto))

    def bind(self, address):
        host, port = address
        check_error(mbedtls_net_bind(
            &self._ctx, host.encode("ascii"), str(port).encode("ascii"),
            self._proto))

    def accept(self):
        # mbedtls_net_accept
        pass

    def setblocking(self, flag):
        if not isinstance(flag, int):
            raise TypeError("an integer is required (got type %s)"
                            % type(flag))
        if flag:
            check_error(_net.mbedtls_net_set_block(&self._ctx))
        else:
            check_error(_net.mbedtls_net_set_nonblock(&self._ctx))
