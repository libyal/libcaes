AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@

TESTS = \
	test_crypt_ecb.sh \
	test_crypt_cbc.sh \
	test_crypt_xts.sh

check_SCRIPTS = \
	test_crypt_cbc.sh \
	test_crypt_ccm.sh \
	test_crypt_cfb.sh \
	test_crypt_ecb.sh \
	test_crypt_xts.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	caes_test_crypt_cbc \
	caes_test_crypt_ccm \
	caes_test_crypt_cfb \
	caes_test_crypt_ecb \
	caes_test_crypt_xts

caes_test_crypt_cbc_SOURCES = \
	caes_test_crypt_cbc.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_cbc_LDADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

caes_test_crypt_ccm_SOURCES = \
	caes_test_crypt_ccm.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_ccm_LDADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

caes_test_crypt_cfb_SOURCES = \
	caes_test_crypt_cfb.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_cfb_LDADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

caes_test_crypt_ecb_SOURCES = \
	caes_test_crypt_ecb.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_ecb_LDADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

caes_test_crypt_xts_SOURCES = \
	caes_test_crypt_xts.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_libcstring.h \
	caes_test_unused.h

caes_test_crypt_xts_LDADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

