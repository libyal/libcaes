AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCAES_DLL_IMPORT@

if HAVE_PYTHON_TESTS
TESTS_PYCAES = \
	test_python_module.sh
endif

TESTS = \
	test_library.sh \
	$(TESTS_PYCAES)

check_SCRIPTS = \
	pycaes_test_crypt_cbc.py \
	pycaes_test_crypt_ccm.py \
	pycaes_test_crypt_ecb.py \
	pycaes_test_crypt_xts.py \
	pycaes_test_support.py \
	test_library.sh \
	test_manpage.sh \
	test_python_module.sh \
	test_runner.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	caes_test_context \
	caes_test_crypt_cbc \
	caes_test_crypt_ccm \
	caes_test_crypt_xts \
	caes_test_error \
	caes_test_support \
	caes_test_tweaked_context

caes_test_context_SOURCES = \
	caes_test_context.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_macros.h \
	caes_test_memory.c caes_test_memory.h \
	caes_test_unused.h

caes_test_context_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_cbc_SOURCES = \
	caes_test_crypt_cbc.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_unused.h

caes_test_crypt_cbc_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_ccm_SOURCES = \
	caes_test_crypt_ccm.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_unused.h

caes_test_crypt_ccm_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_xts_SOURCES = \
	caes_test_crypt_xts.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_unused.h

caes_test_crypt_xts_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_error_SOURCES = \
	caes_test_error.c \
	caes_test_libcaes.h \
	caes_test_macros.h \
	caes_test_unused.h

caes_test_error_LDADD = \
	../libcaes/libcaes.la

caes_test_support_SOURCES = \
	caes_test_libcaes.h \
	caes_test_macros.h \
	caes_test_support.c \
	caes_test_unused.h

caes_test_support_LDADD = \
	../libcaes/libcaes.la

caes_test_tweaked_context_SOURCES = \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_macros.h \
	caes_test_memory.c caes_test_memory.h \
	caes_test_tweaked_context.c \
	caes_test_unused.h

caes_test_tweaked_context_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	-rm -f Makefile

