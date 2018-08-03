from __future__ import print_function

import socket

from mbedtls.x509 import Certificate
from mbedtls.tls import *


HOST = "localhost"
PORT = 4433


def block(callback, *args, **kwargs):
    while True:
        try:
            return callback(*args, **kwargs)
        except (WantReadError, WantWriteError):
            pass


def main(host, port):
    store = TrustStore.from_pem_file("srv.crt")

    conf = TLSConfiguration(
        lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
        highest_supported_version=TLSVersion.MAXIMUM_SUPPORTED,
        trust_store=store,
        validate_certificates=False,
    )

    ctx = ClientContext(conf)
    assert ctx._purpose is Purpose.CLIENT_AUTH, ctx._purpose

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        server_hostname="localhost")
    sock.settimeout(1.0)
    assert isinstance(sock, TLSWrappedSocket)

    print("  . TLS Version: ", sock.negotiated_tls_version())
    print("  . protocol: ", sock.negotiated_protocol())
    print("  . cipher: ", sock.cipher())

    sock.connect((host, port))
    block(sock.do_handshake)

    print("  . Handshake OK")
    print("  . TLS Version: ", sock.negotiated_tls_version())
    print("  . protocol: ", sock.negotiated_protocol())
    print("  . cipher: ", sock.cipher())

    request = b"GET / HTTP/1.0\r\n\r\n"
    print("  > write to server:", request)
    block(sock.send, request)

    print("  < Read from server:", end=" ")
    data = block(sock.recv, 1024)
    print(data)

    sock.close()


if __name__ == "__main__":
    main(HOST, PORT)
