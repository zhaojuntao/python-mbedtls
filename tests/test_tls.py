import multiprocessing as mp
import socket

import pytest

from mbedtls.exceptions import TLSError
from mbedtls.tls import *


class TestTrustStore:
    @pytest.fixture
    def store(self):
        return TrustStore.system()

    def test_default(self):
        assert not TrustStore()

    def test_eq(self, store):
        other = TrustStore.from_pem_file(certifi.where())
        assert store == other

    def test_len(self, store):
        assert len(frozenset(store)) == 132

    def test_iter(self, store):
        for n, _ in enumerate(store, start=1):
            pass
        assert n == len(store)

    def test_contains(self, store):
        cert = next(iter(store))
        assert cert in store


class TestTLSConfiguration:

    @pytest.fixture
    def conf(self):
        return TLSConfiguration()

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf_ = conf.update(validate_certificates=validate)
        assert conf_.validate_certificates is validate

    @pytest.mark.parametrize("chain", [()])
    def test_set_certificate_chain(self, conf, chain):
        conf_ = conf.update(certificate_chain=chain)
        assert conf_.certificate_chain == chain

    @pytest.mark.parametrize("ciphers", [ciphers_available()])
    def test_set_ciphers(self, conf, ciphers):
        conf_ = conf.update(ciphers=ciphers)
        assert conf_.ciphers == ciphers

    @pytest.mark.parametrize(
        "inner_protocols",
        [[], (), [NextProtocol.H2, NextProtocol.H2C],
         [b'h2', b'h2c', b'ftp']])
    def test_set_inner_protocols(self, conf, inner_protocols):
        conf_ = conf.update(inner_protocols=inner_protocols)
        assert conf_.inner_protocols == tuple(
            NextProtocol(_) for _ in inner_protocols)

    @pytest.mark.parametrize("version", TLSVersion)
    def test_lowest_supported_version(self, conf, version):
        conf_ = conf.update(lowest_supported_version=version)
        assert conf_.lowest_supported_version is version

    @pytest.mark.parametrize("version", TLSVersion)
    def test_highest_supported_version(self, conf, version):
        conf_ = conf.update(highest_supported_version=version)
        assert conf_.highest_supported_version is version

    @pytest.mark.parametrize("store", [TrustStore.system()])
    def test_trust_store(self, conf, store):
        conf_ = conf.update(trust_store=store)
        assert conf_.trust_store == store

    @pytest.mark.parametrize("callback", [None])
    def test_set_sni_callback(self, conf, callback):
        assert conf.sni_callback is None


class TestBaseContext:
    @pytest.fixture(params=[Purpose.SERVER_AUTH, Purpose.CLIENT_AUTH])
    def purpose(self, request):
        return request.param

    @pytest.fixture
    def conf(self, purpose):
        return TLSConfiguration(validate_certificates=False)

    @pytest.fixture(params=[ServerContext, ClientContext])
    def context(self, conf, request):
        cls = request.param
        return cls(conf)

    def test_get_configuration(self, context, conf):
        assert conf
        assert context.configuration is conf

    def test_selected_npn_protocol(self, context):
        assert context._selected_npn_protocol() is None

    def test_cipher(self, context):
        assert context._cipher() is None

    def test_get_channel_binding(self, context):
        assert context._get_channel_binding() is None

    def test_negotiated_tls_version(self, context):
        assert context._negotiated_tls_version() is TLSVersion.SSLv3


class TestClientContext:
    @pytest.fixture
    def conf(self):
        return TLSConfiguration(validate_certificates=False)

    @pytest.fixture
    def context(self, conf):
        return ClientContext(conf)


class TestServerContext:
    @pytest.fixture
    def conf(self):
        return TLSConfiguration(validate_certificates=False)

    @pytest.fixture
    def context(self, conf):
        return ServerContext(conf)


class TestTLSCommunication:
    @pytest.fixture(scope="class")
    def host(self):
        return "localhost"

    @pytest.fixture(scope="class")
    def port(self):
        return 50008

    @pytest.fixture(scope="class")
    def srv_conf(self):
        return TLSConfiguration(validate_certificates=False)

    @pytest.fixture
    def cli_conf(self):
        return TLSConfiguration(validate_certificates=False)

    @pytest.fixture
    def client(self, cli_conf, host, port):
        ctx = ClientContext(cli_conf)
        # XXX Also test hostname verfication!
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=None)
        assert isinstance(sock, TLSWrappedSocket)
        sock.settimeout(2.0)
        sock.connect((host, port))
        yield sock
        sock.close()

    @pytest.fixture(scope="class")
    def server(self, srv_conf, host, port):
        ctx = ServerContext(srv_conf)
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        # sock.listen(5)

        def run(pipe):
            # accept() is blocking.
            conn, addr = sock.accept()
            assert conn.fileno() != sock.fileno()
            data = conn.recv(1024)
            pipe.send(data)
            conn.close()

        parent_conn, child_conn = mp.Pipe()
        runner = mp.Process(target=run, args=(child_conn,))
        runner.start()
        yield parent_conn

        # XXX Next requires a forking server.
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        #     cli.connect((host, port))
        #     cli.sendall(b"bye")
        runner.join(0.1)
        sock.close()

    def test_client_server_not_encrypted(self, client, server):
        client.do_handshake()
        client.sendall(b"hello")
        assert server.recv() == b"hello"
