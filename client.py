import socket

from mbedtls.x509 import Certificate
from mbedtls.tls import *


HOST = None  # "localhost"
# PORT = 50007
PORT = 4433


def main(host, port):
    store = TrustStore.from_pem_file("srv.crt")

    conf = TLSConfiguration._create_default_context(
        purpose=Purpose.CLIENT_AUTH).update(
            trust_store=store,
            # highest_supported_version=TLSVersion.SSLv3,
            validate_certificates=False)
    print(conf)

    ctx = ClientContext(conf)
    print(ctx)

    sock = ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        server_hostname="localhost")
    assert isinstance(sock, TLSWrappedSocket)
    print(sock)

    sock.connect((host, port))
    sock.do_handshake()


if __name__ == "__main__":
    main(HOST, PORT)
