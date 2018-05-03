"""Unit tests for mbedtls.pk."""


from itertools import product
from functools import partial
from tempfile import TemporaryFile

import pytest

import mbedtls.hash as _hash
from mbedtls.exceptions import *
from mbedtls.exceptions import _ErrorBase
from mbedtls.pk import _type_from_name, _get_md_alg, CipherBase
from mbedtls.pk import *

try:
    long
except NameError:
    long = int


def test_cipher_list():
    assert len(CIPHER_NAME) == 5


def test_supported_curves():
    assert get_supported_curves()


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert tuple(cl) == CIPHER_NAME


@pytest.mark.parametrize(
    "md_algorithm", [vars(_hash)[name] for name in _hash.algorithms_available])
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), _hash.Hash)


class _TestCipherBase(object):

    @pytest.fixture
    def key(self):
        raise NotImplementedError

    def test_cipher_without_key(self):
        assert self.cipher.has_public() is False
        assert self.cipher.has_private() is False

    @pytest.mark.usefixtures("key")
    def test_generate(self):
        assert self.cipher.has_public() is True
        assert self.cipher.has_private() is True

    @pytest.mark.usefixtures("key")
    def test_type_accessor(self):
        assert self.cipher._type == _type_from_name(self.cipher.name)

    def test_key_size_accessor(self):
        assert self.cipher.key_size == 0

    @pytest.mark.usefixtures("key")
    def test_key_size_accessor_with_key(self):
        assert self.cipher.key_size != 0

    @pytest.mark.usefixtures("key")
    def test_check_pair(self):
        assert check_pair(self.cipher, self.cipher) is True

    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name)
    def test_sign_without_key_returns_none(self, digestmod, randbytes):
        message = randbytes(4096)
        assert self.cipher.sign(message, digestmod) is None

    @pytest.mark.usefixtures("key")
    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name)
    def test_sign_verify(self, digestmod, randbytes):
        msg = randbytes(4096)
        sig = self.cipher.sign(msg, digestmod)
        assert sig is not None
        assert self.cipher.verify(msg, sig, digestmod) is True
        assert self.cipher.verify(msg + b"\0", sig, digestmod) is False

    @pytest.mark.usefixtures("key")
    def test_import_public_key(self):
        other = type(self.cipher)()

        prv, pub = self.cipher.to_DER()
        other.from_buffer(pub)
        assert other.has_private() is False
        assert other.has_public() is True
        assert check_pair(self.cipher, other) is False  # Test private half.
        assert check_pair(other, self.cipher) is True  # Test public half.
        assert check_pair(other, other) is False
        assert self.cipher != other

    @pytest.mark.usefixtures("key")
    def test_import_private_key(self):
        other = type(self.cipher)()

        prv, pub = self.cipher.to_DER()
        other.from_buffer(prv)
        assert other.has_private() is True
        assert other.has_public() is True
        assert check_pair(self.cipher, other) is True  # Test private half.
        assert check_pair(other, self.cipher) is True  # Test public half.
        assert check_pair(other, other) is True
        assert self.cipher == other

    @pytest.mark.usefixtures("key")
    def test_to_PEM(self):
        other = type(self.cipher)()

        prv, pub = self.cipher.to_PEM()
        other.from_PEM(prv)
        assert self.cipher == other


class TestRSA(_TestCipherBase):

    @pytest.fixture(autouse=True)
    def rsa(self):
        self.cipher = RSA()
        yield
        self.cipher = None

    @pytest.fixture
    def key(self):
        key_size = 1024
        self.cipher.generate(key_size)

    @pytest.mark.usefixtures("key")
    def test_encrypt_decrypt(self, randbytes):
        msg = randbytes(self.cipher.key_size - 11)
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg


class TestECC(_TestCipherBase):

    @pytest.fixture(autouse=True, params=get_supported_curves())
    def ecp(self, request):
        curve = request.param
        self.cipher = ECC(curve)
        yield
        self.cipher = None

    @pytest.fixture
    def key(self):
        self.cipher.generate()

    def test_public_value_accessor_without_key(self):
        assert self.cipher.public_value == 0

    def test_private_value_accessor_without_key(self):
        assert self.cipher.private_value == 0

    @pytest.mark.usefixtures("key")
    def test_public_value_accessor(self):
        pub = self.cipher.public_value
        assert isinstance(pub.x, long)
        assert isinstance(pub.y, long)
        assert isinstance(pub.z, long)
        assert pub.x not in (0, pub.y, pub.z)
        assert pub.y not in (0, pub.x, pub.z)
        assert pub.z in (0, 1)

    @pytest.mark.usefixtures("key")
    def test_private_value_accessor(self):
        prv = self.cipher.private_value
        assert isinstance(prv, long)
        assert prv != 0


class TestECCtoECDH:

    @pytest.fixture(autouse=True, params=get_supported_curves())
    def _setup(self, request):
        curve = request.param
        ecp = ECC(curve)
        ecp.generate()
        self.srv = ecp.to_ECDH_server()
        self.cli = ecp.to_ECDH_client()

    def test_exchange(self):
        public = self.cli.make_public()
        assert self.cli.has_public() is True

        self.srv.read_public(public)
        assert self.srv.has_peers_public() is True

        srv_sec = self.srv.calc_secret()
        cli_sec = self.cli.calc_secret()
        assert srv_sec == cli_sec


class TestECDHE:
    # From test_suite_ecdh.function

    @pytest.fixture(autouse=True, params=get_supported_curves())
    def _setup(self, request):
        curve = request.param
        self.srv = ECDHServer(curve)
        self.cli = ECDHClient(curve)

    def test_cipher_without_key(self):
        for cipher in (self.srv, self.cli):
            assert cipher.has_private() is False
            assert cipher.has_public() is False

    def test_exchange(self):
        params = self.srv.make_params()
        assert self.srv.has_private() is True

        self.cli.read_params(params)
        assert self.cli.has_peers_public() is True

        public = self.cli.make_public()
        assert self.cli.has_public() is True

        self.srv.read_public(public)
        assert self.srv.has_peers_public() is True

        srv_sec = self.srv.calc_secret()
        cli_sec = self.cli.calc_secret()
        assert srv_sec == cli_sec
        # assert self.srv.shared_secret == srv_sec
        # assert self.cli.shared_secret == cli_sec
