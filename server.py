import socket
import time

# import certifi

from mbedtls.pk import RSA
from mbedtls.x509 import Certificate
from mbedtls.tls import *

HOST = "localhost"
PORT = 4433


def main(host, port):
    cert = Certificate.from_file("srv.crt")
    print(cert._info())

    store = TrustStore.from_pem_file("srv.crt")

    key = RSA()
    with open("srv.key", "rt") as k:
        key.from_PEM(k.read())

    conf = TLSConfiguration(
        certificate_chain=([cert], key),
        # highest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
        trust_store=store,
        validate_certificates=False)

    ctx = ServerContext(conf)
    assert ctx._purpose is Purpose.SERVER_AUTH, ctx._purpose

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    assert isinstance(sock, TLSWrappedSocket)

    print("binding to %r:%i" % (host, port))
    sock.bind((host, port))
    sock.listen()

    print("  . TLS Version: ", sock.negotiated_tls_version())
    print("  . protocol: ", sock.negotiated_protocol())
    print("  . cipher: ", sock.cipher())
    print("  . Waiting for client...")

    try:
        while True:
            cli, address = sock.accept()
            cli.do_handshake()

            print("  . TLS Version: ", sock.negotiated_tls_version())
            print("  . protocol: ", sock.negotiated_protocol())
            print("  . cipher: ", sock.cipher())

            print("  < Read from client", end=" ")
            request = cli.recv(1024)
            print(request)
            print("  > Write to client", end=" ")
            cli.send(b"bye")

    except KeyboardInterrupt:
        sock.close()


if __name__ == "__main__":
    main(HOST, PORT)
