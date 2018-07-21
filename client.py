import socket

from mbedtls.x509 import Certificate
from mbedtls.tls import *


HOST = None  # "localhost"
# PORT = 50007
PORT = 4433


def main(host, port):
    store = TrustStore.from_pem_file("srv.crt")

    conf = TLSConfiguration(
        # trust_store=store,
        validate_certificates=False,
    )
    print(conf)

    ctx = ClientContext(conf)
    assert ctx._purpose is Purpose.CLIENT_AUTH, ctx._purpose
    print(ctx)

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        server_hostname="localhost")
    assert isinstance(sock, TLSWrappedSocket)
    print(sock)

    sock.connect((host, port))
    print(sock.context._state)
    # sock.do_handshake()
    while True:
        state = sock.context._do_handshake_step()
        print(".", state)
        if state == 16:
            break


if __name__ == "__main__":
    main(HOST, PORT)
