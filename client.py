import socket

from mbedtls.tls import *


HOST = None  # "localhost"
# PORT = 50007
PORT = 4433


def main(host, port):
    conf = TLSConfiguration._create_default_context(
        purpose=Purpose.CLIENT_AUTH).update(
            validate_certificates=False)
    print(conf)

    ctx = ClientContext(conf)
    print(ctx)

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        None)
    assert isinstance(sock, TLSWrappedSocket)
    print(sock)

    sock.connect((host, port))


if __name__ == "__main__":
    main(HOST, PORT)
