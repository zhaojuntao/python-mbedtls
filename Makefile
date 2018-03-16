.DEFAULT_GOAL := debug

PYX  = $(wildcard mbedtls/*.pyx)
PYX += $(wildcard mbedtls/cipher/*.pyx)

LIBMBEDTLS = $(HOME)/lib/mbedtls-2.4.2

debug:
	cython -X linetrace=True $(PYX)
	python setup.py build_ext --force --inplace --define CYTHON_TRACE \
		   -L$(LIBMBEDTLS)/lib \
		   -I$(LIBMBEDTLS)/include

html:
	cd docs && make html

clean:
	$(RM) mbedtls/*.c mbedtls/*.so mbedtls/*.pyc mbedtls/*.html
	$(RM) mbedtls/cipher/*.c mbedtls/cipher/*.so mbedtls/cipher/*.pyc \
		mbedtls/cipher/*.html
	$(RM) mbedtls/pk/*.c mbedtls/pk/*.so mbedtls/pk/*.pyc mbedtls/pk/*.html
	$(RM) -r build dist
