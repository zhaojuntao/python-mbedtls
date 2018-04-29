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


def test_cipher_list():
    assert len(CIPHER_NAME) == 5


def test_supported_curves():
    assert get_supported_curves()


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert tuple(cl) == CIPHER_NAME


@pytest.mark.parametrize(
    "md_algorithm", (vars(_hash)[name] for name in _hash.algorithms_available))
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), _hash.Hash)


class _TestCipherBase(object):

    @pytest.fixture
    def key(self):
        pass

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
    def test_check_pair(self):
        assert check_pair(self.cipher, self.cipher) is True

    def test_sign_without_key_returns_none(self, randbytes):
        message = randbytes(4096)
        assert self.cipher.sign(message, _hash.md5) is None


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

    @pytest.mark.usefixtures("key")
    @pytest.mark.parametrize(
        "digestmod",
        (_get_md_alg(name) for name in _hash.algorithms_available),
        ids=lambda dm: dm().name)
    def test_sign_verify(self, digestmod, randbytes):
        if digestmod().name == "ripemd160":
            pytest.skip("ripemd160 fails")
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

    @pytest.mark.usefixtures("key")
    def test_to_PEM(self):
        other = type(self.cipher)()

        prv, pub = self.cipher.to_PEM()
        other.from_PEM(prv)
        assert self.cipher.to_DER() == other.to_DER()


class TestEC(_TestCipherBase):

    @pytest.fixture(autouse=True,
                    params=[ECKEY, ECKEY_DH, ECDSA])
    def ecp(self, request):
        cls = request.param
        self.cipher = cls()
        yield
        self.cipher = None

    @pytest.fixture(params=get_supported_curves())
    def key(self, request):
        curve = request.param
        self.cipher.generate(curve)
