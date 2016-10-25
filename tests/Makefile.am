AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCAES_DLL_IMPORT@

if HAVE_PYTHON
TESTS_PYCAES = \
	test_python_functions.sh
endif

TESTS = \
	test_api_functions.sh \
	test_api_types.sh \
	$(TESTS_PYCAES)

check_SCRIPTS = \
	pycaes_test_crypt_cbc.py \
	pycaes_test_crypt_ccm.py \
	pycaes_test_crypt_ecb.py \
	pycaes_test_crypt_xts.py \
	pycaes_test_get_version.py \
	test_api_functions.sh \
	test_python_functions.sh \
	test_runner.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	caes_test_context \
	caes_test_crypt_cbc \
	caes_test_crypt_ccm \
	caes_test_crypt_cfb \
	caes_test_crypt_ecb \
	caes_test_crypt_xts \
	caes_test_error \
	caes_test_support \
	caes_test_tweaked_context

caes_test_context_SOURCES = \
	caes_test_context.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_macros.h \
	caes_test_memory.c caes_test_memory.h \
	caes_test_unused.h

caes_test_context_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_crypt_cbc_SOURCES = \
	caes_test_crypt_cbc.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_cbc_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_crypt_ccm_SOURCES = \
	caes_test_crypt_ccm.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_ccm_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_crypt_cfb_SOURCES = \
	caes_test_crypt_cfb.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_cfb_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_crypt_ecb_SOURCES = \
	caes_test_crypt_ecb.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_ecb_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_crypt_xts_SOURCES = \
	caes_test_crypt_xts.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_xts_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

caes_test_error_SOURCES = \
	caes_test_error.c \
	caes_test_libcaes.h \
	caes_test_libcstring.h \
	caes_test_macros.h \
	caes_test_unused.h

caes_test_error_LDADD = \
	../libcaes/libcaes.la \
	@LIBCSTRING_LIBADD@

caes_test_support_SOURCES = \
	caes_test_libcaes.h \
	caes_test_libcstring.h \
	caes_test_macros.h \
	caes_test_support.c \
	caes_test_unused.h

caes_test_support_LDADD = \
	../libcaes/libcaes.la \
	@LIBCSTRING_LIBADD@

caes_test_tweaked_context_SOURCES = \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_macros.h \
	caes_test_memory.c caes_test_memory.h \
	caes_test_tweaked_context.c \
	caes_test_unused.h

caes_test_tweaked_context_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

