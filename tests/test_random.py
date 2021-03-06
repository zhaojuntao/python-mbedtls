"""Unit tests for mbedtls.random."""
# pylint: disable=missing-docstring

import random as _random

# pylint: disable=import-error
import mbedtls.random as _drbg
# pylint: enable=import-error

import pytest

from mbedtls.exceptions import TLSError


def sample(start, end, k=20):
    return _random.sample(range(start, end), k)


@pytest.fixture
def entropy():
    return _drbg.Entropy()


@pytest.fixture
def random():
    return _drbg.Random()


def test_entropy_gather(entropy):
    # Only test that this does not raise.
    entropy.gather()


@pytest.mark.parametrize("length", sample(0, 64))
def test_entropy_retrieve(entropy, length):
    assert len(entropy.retrieve(length)) == length


@pytest.mark.parametrize("length", (100, ))
def test_entropy_retrieve_long_block_raises_exception(entropy, length):
    with pytest.raises(TLSError):
        entropy.retrieve(length)


def test_entropy_update(entropy, randbytes):
    # Only test that this does not raise.
    buf = randbytes(64)
    entropy.update(buf)


def test_entropy_not_reproducible(entropy):
    assert entropy.retrieve(8) != entropy.retrieve(8)


def test_entropy_random_initial_values(entropy):
    # pylint: disable=invalid-name
    other = _drbg.Entropy()
    assert entropy.retrieve(8) != other.retrieve(8)


def test_reseed(random):
    random.reseed()


def test_not_reproducible(random):
    assert random.token_bytes(8) != random.token_bytes(8)


def test_update(random):
    random.update(b"additional data")


def test_initial_values(random):
    other = _drbg.Random()
    assert random.token_bytes(8) != other.token_bytes(8)


@pytest.mark.parametrize("length", sample(0, 1024))
def test_token_bytes(random, length):
    assert len(random.token_bytes(length)) == length


@pytest.mark.parametrize("length", sample(0, 1024))
def test_token_hex(random, length):
    assert len(random.token_hex(length)) == 2 * length
