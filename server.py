import socket

# import certifi

from mbedtls.pk import RSA
from mbedtls.x509 import Certificate
from mbedtls.tls import *

HOST = None  # "localhost"
# PORT = 50007
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
    assert isinstance(sock, TLSWrappedSocket)

    print("binding to %r:%i" % (host, port))
    sock.bind((host, port))

    print("waiting for client...")

    cli, address = sock.accept()
    print(cli, address)

    print(cli.context._state)
    # cli.do_handshake()
    while True:
        state = cli.context._do_handshake_step()
        print(".", state)
        if state == 16:
            break


if __name__ == "__main__":
    main(HOST, PORT)
