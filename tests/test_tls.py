import pytest

from mbedtls.tls import *
from mbedtls.tls import _TLSConfiguration


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
        assert len(store) >= 10

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
        return _TLSConfiguration()

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf.set_validate_certificates(validate)

    @pytest.mark.parametrize("chain", [None, []])
    def test_set_certificate_chain(self, conf, chain):
        # XXX
        conf.set_certificate_chain(chain)

    @pytest.mark.parametrize("ciphers", [None, []])
    def test_set_ciphers(self, conf, ciphers):
        # XXX
        conf.set_ciphers(ciphers)

    @pytest.mark.parametrize("protocols", [None])
    def test_set_inner_protocols(self, conf, protocols):
        # XXX
        conf.set_inner_protocols(protocols)

    @pytest.mark.parametrize("version", [None, TLSVersion.MINIMUM_SUPPORTED])
    def test_set_lowest_supported_version(self, conf, version):
        conf.set_lowest_supported_version(version)

    @pytest.mark.parametrize("version", [None, TLSVersion.MAXIMUM_SUPPORTED])
    def test_set_highest_supported_version(self, conf, version):
        conf.set_highest_supported_version(version)

    @pytest.mark.parametrize("store", [None])
    def test_set_trust_store(self, conf, store):
        # XXX
        conf.set_trust_store(store)

    @pytest.mark.parametrize("callback", [None])
    def test_set_sni_callback(self, conf, callback):
        # XXX
        conf.set_sni_callback(callback)
