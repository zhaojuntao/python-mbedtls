"""Net socket wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls._net as _net

import socket

from mbedtls.exceptions import *


cdef class Socket:
    def __init__(self):
        self._proto = _net.MBEDTLS_NET_PROTO_TCP
        self._timeout = socket.getdefaulttimeout()

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

    def recv(self, size_t bufsize, flags=0):
        if flags:
            raise NotImplementedError("flags not supported")
        cdef unsigned char* buffer = <unsigned char *>malloc(
            bufsize * sizeof(unsigned char))
        if not buffer:
            raise MemoryError()
        try:
            if self._timeout:
                sz = check_error(mbedtls_net_recv_timeout(
                    &self._ctx,
                    &buffer[0],
                    bufsize,
                    int(self._timeout)))
            else:
                sz = check_error(mbedtls_net_recv(
                    &self._ctx,
                    &buffer[0],
                    bufsize))
            return bytes(buffer[:sz])
        finally:
            free(buffer)

    def send(self, const unsigned char[:] message, flags=0):
        if flags:
            raise NotImplementedError("flags not supported")
        sz = check_error(mbedtls_net_send(
            &self._ctx,
            &message[0],
            message.size))
