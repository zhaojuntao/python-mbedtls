import multiprocessing as mp
import socket

import pytest

from mbedtls.exceptions import _ErrorBase
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
        return TLSConfiguration._create_default_context(purpose=purpose)

    @pytest.fixture(params=[ServerContext, ClientContext])
    def context(self, conf, request):
        cls = request.param
        return cls(conf)

    def test_get_configuration(self, context, conf):
        assert context.configuration is conf

    @pytest.mark.xfail(raises=_ErrorBase, strict=True)
    def test_read_amt(self, context):
        context.read(12)

    def test_read_buf_amt(self, context):
        buf = bytearray(32)
        context.read(buf, 12)
        assert buf == bytearray(32)

    @pytest.mark.xfail(raises=_ErrorBase, strict=True)
    def test_write_buf(self, context):
        buf = bytearray(32)
        context.write(buf)

    def test_selected_npn_protocol(self, context):
        assert context.selected_npn_protocol() is None

    def test_selected_alpn_protocol(self, context):
        assert context.selected_alpn_protocol() is None

    def test_cipher(self, context):
        assert context.cipher() is None

    @pytest.mark.xfail(raises=_ErrorBase, strict=True)
    def test_do_handshake(self, context):
        context.do_handshake()

    @pytest.mark.xfail(raises=_ErrorBase, strict=True)
    def test_renegotiate(self, context):
        context.renegotiate()

    def test_get_channel_binding(self, context):
        assert context.get_channel_binding() is None

    def test_version(self, context):
        assert context.version() is TLSVersion.SSLv3


class TestClientContext:
    @pytest.fixture
    def conf(self):
        return TLSConfiguration._create_default_context(
            purpose=Purpose.CLIENT_AUTH)

    @pytest.fixture
    def context(self, conf):
        return ClientContext(conf)


class TestServerContext:
    @pytest.fixture
    def conf(self):
        return TLSConfiguration._create_default_context(
            purpose=Purpose.SERVER_AUTH)

    @pytest.fixture
    def context(self, conf):
        return ServerContext(conf)


class TestTLSCommunication:
    @pytest.fixture(scope="class")
    def host(self):
        return "localhost"

    @pytest.fixture(scope="class")
    def port(self):
        return 50007

    @pytest.fixture(scope="class")
    def tcp_srv_socket(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        yield sock
        sock.close()

    @pytest.fixture(scope="class")
    def tls_srv_conf(self):
        return TLSConfiguration._create_default_context(
            purpose=Purpose.SERVER_AUTH)

    @pytest.fixture(scope="class")
    def tls_srv_socket(self, tls_srv_conf, tcp_srv_socket):
        ctx = ServerContext(tls_srv_conf)
        sock = ctx.wrap_socket(tcp_srv_socket)
        return sock

    @pytest.fixture
    def tls_cli_conf(self):
        return TLSConfiguration._create_default_context(
            purpose=Purpose.CLIENT_AUTH)

    @pytest.fixture
    def tls_cli_context(self, tls_cli_conf):
        return ClientContext(tls_cli_conf)

    @pytest.fixture(scope="class")
    def tcp_server(self, tcp_srv_socket, host, port):
        parent_conn, child_conn = mp.Pipe()

        def run(pipe):
            while True:
                conn, addr = tcp_srv_socket.accept()
                data = conn.recv(1024)
                pipe.send(data)
                conn.close()
                if data == b"bye":
                    break

        runner = mp.Process(target=run, args=(child_conn,))
        runner.start()
        yield parent_conn

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            sock.sendall(b"bye")
        runner.join(0.1)

    @pytest.fixture(scope="function")
    def tcp_client(self, tcp_server, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((host, port))
        yield sock
        sock.close()

    def test_client_server(self, tcp_server, tcp_client):
        tcp_client.sendall(b"hello")
        assert tcp_server.recv() == b"hello"
