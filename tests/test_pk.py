"""Unit tests for mbedtls.pk."""


from functools import partial
from tempfile import TemporaryFile

import pytest

import mbedtls.hash as _hash
from mbedtls.exceptions import *
from mbedtls.exceptions import _ErrorBase
from mbedtls.pk import _type_from_name, _get_md_alg, CipherBase
from mbedtls.pk import *


@pytest.fixture(params=(name for name in sorted(get_supported_ciphers())
                        if name != b"NONE"))
def cipher(request):
    name = request.param
    return CipherBase(name)


# @pytest.fixture(params=[RSA, ECKEY, ECKEY_DH, ECDSA])
@pytest.fixture(params=[RSA])
def rsa(request):
    key_size = 1024
    cipher = request.param()
    if request.param is RSA:
        cipher.generate(key_size)
    else:
        cipher.generate()
    return cipher


def test_ec_generate():
    ec = ECKEY()
    assert not ec.has_public()
    assert not ec.has_private()
    ec.generate()
    assert ec.has_public()
    assert ec.has_private()


def test_cipher_list():
    assert len(CIPHER_NAME) == 5


def test_supported_curves():
    assert get_supported_curves()


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert tuple(cl) == CIPHER_NAME


def test_type_from_name():
    assert tuple(_type_from_name(name)
                 for name in CIPHER_NAME) == tuple(range(len(CIPHER_NAME)))


def test_type_accessor(cipher):
    assert cipher._type == _type_from_name(cipher.name)


def test_key_size_accessor(cipher):
    assert cipher.key_size == 0


@pytest.mark.parametrize(
    "algorithm", (_get_md_alg(name) for name in _hash.algorithms_available))
def test_digestmod(algorithm):
    assert isinstance(algorithm(), _hash.Hash)


@pytest.mark.parametrize(
    "md_algorithm", (vars(_hash)[name] for name in _hash.algorithms_available))
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), _hash.Hash)


def test_rsa_encrypt_decrypt(rsa, randbytes):
    msg = randbytes(rsa.key_size - 11)
    assert rsa.decrypt(rsa.encrypt(msg)) == msg


def test_rsa_sign_without_key_returns_none(randbytes):
    rsa = RSA()
    message = randbytes(4096)
    assert rsa.sign(message, _hash.md5) is None


def test_rsa_check_pair(rsa):
    assert check_pair(rsa, rsa) is True


def test_rsa_has_private_and_has_public_with_private_key(rsa):
    cipher = RSA()
    assert cipher.has_private() is False
    assert cipher.has_public() is False

    prv, pub = rsa.to_DER()
    cipher.from_buffer(prv)
    assert cipher.has_private() is True
    assert cipher.has_public() is True


def test_rsa_has_private_and_has_public_with_public_key(rsa):
    cipher = RSA()
    assert cipher.has_private() is False
    assert cipher.has_public() is False

    prv, pub = rsa.to_DER()
    cipher.from_buffer(pub)
    assert cipher.has_private() is False
    assert cipher.has_public() is True


def test_rsa_import_public_key(rsa):
    cipher = RSA()

    prv, pub = rsa.to_DER()
    cipher.from_buffer(pub)
    assert check_pair(rsa, cipher) is False  # Test private half.
    assert check_pair(cipher, rsa) is True   # Test public half.
    assert check_pair(cipher, cipher) is False


def test_rsa_import_private_key(rsa):
    cipher = RSA()
    prv, pub = rsa.to_DER()
    cipher.from_buffer(prv)
    assert check_pair(rsa, cipher) is True  # Test private half.
    assert check_pair(cipher, rsa) is True # Test public half.
    assert check_pair(cipher, cipher) is True


def test_rsa_to_PEM(rsa):
    cipher = RSA()
    prv, pub = rsa.to_PEM()
    cipher.from_PEM(prv)
    assert cipher.has_private() is True
    assert cipher.has_public() is True
    assert check_pair(rsa, cipher) is True  # Test private half.
    assert check_pair(cipher, rsa) is True  # Test public half.
    assert check_pair(cipher, cipher) is True


def test_rsa_to_DER(rsa):
    cipher = RSA()
    prv, pub = rsa.to_DER()
    cipher.from_DER(prv)
    assert cipher.has_private() is True
    assert cipher.has_public() is True
    assert check_pair(rsa, cipher) is True  # Test private half.
    assert check_pair(cipher, rsa) is True  # Test public half.
    assert check_pair(cipher, cipher) is True


@pytest.mark.parametrize("digestmod", (_hash.md5, None))
def test_rsa_sign_verify(rsa, digestmod, randbytes):
    message = randbytes(4096)
    sig = rsa.sign(message, digestmod)
    assert sig is not None
    assert rsa.verify(message, sig, digestmod) is True
    assert rsa.verify(message + b"\0", sig, digestmod) is False
