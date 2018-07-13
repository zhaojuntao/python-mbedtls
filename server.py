import socket

from mbedtls.x509 import Certificate
from mbedtls.tls import *

HOST = None  # "localhost"
# PORT = 50007
PORT = 4433


def main(host, port):
    # cert = Certificate.from_file("./tests/ca/wikipedia.pem")
    # print(cert._info())

    conf = TLSConfiguration._create_default_context().update(
        validate_certificates=False)
    print(conf)

    ctx = ServerContext(conf)
    print(ctx)

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    assert isinstance(sock, TLSWrappedSocket)
    print(sock)

    print("binding to %r:%i" % (host, port))
    sock.bind((host, port))

    print("waiting for client...")

    cli, address = sock.accept()
    print(cli, address)

    ctx.do_handshake()


if __name__ == "__main__":
    main(HOST, PORT)
