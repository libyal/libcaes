AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@LIBCAES_DLL_IMPORT@

check_PYTHONdir = $(abs_top_builddir)

BUILT_SOURCES = package.m4

check_AUTOTESTS = \
	test_library \
	test_manpages

if HAVE_PYTHON_TESTS
check_AUTOTESTS += test_python_module
endif

check_PYTHON_SCRIPTS = \
	pycaes_test_context.py \
	pycaes_test_crypt_cbc.py \
	pycaes_test_crypt_ccm.py \
	pycaes_test_crypt_ecb.py \
	pycaes_test_crypt_xts.py \
	pycaes_test_support.py \
	pycaes_test_tweaked_context.py

check_PROGRAMS = \
	caes_test_context \
	caes_test_crypt_cbc \
	caes_test_crypt_ccm \
	caes_test_crypt_ecb \
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
	caes_test_macros.h \
	caes_test_unused.h

caes_test_crypt_cbc_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_ccm_SOURCES = \
	caes_test_crypt_ccm.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_macros.h \
	caes_test_unused.h

caes_test_crypt_ccm_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_ecb_SOURCES = \
	caes_test_crypt_ecb.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_macros.h \
	caes_test_unused.h

caes_test_crypt_ecb_LDADD = \
	../libcaes/libcaes.la \
	@LIBCERROR_LIBADD@

caes_test_crypt_xts_SOURCES = \
	caes_test_crypt_xts.c \
	caes_test_libcaes.h \
	caes_test_libcerror.h \
	caes_test_macros.h \
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

AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

SUFFIXES = .at

.at:
	$(AM_V_GEN)rm -f $@ $@.tmp; \
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $< && \
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status tests/$@

check-build: $(check_PROGRAMS)

check-local: $(check_AUTOTESTS)
	@fail=0; \
	for test_suite in $(check_AUTOTESTS); do \
		$(AM_TESTS_ENVIRONMENT) $(SHELL) "./$$test_suite" $(TESTSUITEFLAGS) || fail=1; \
		echo ""; \
	done; \
	exit $$fail

clean-local:
	for test_suite in $(check_AUTOTESTS); do \
		test ! -f "$$test_suite" || $(SHELL) "./$$test_suite" --clean; \
	done

package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):; \
	{ \
	  echo 'm4_define([AT_PACKAGE_NAME], [$(PACKAGE_NAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_TARNAME], [$(PACKAGE_TARNAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_VERSION], [$(PACKAGE_VERSION)])' ; \
	  echo 'm4_define([AT_PACKAGE_STRING], [$(PACKAGE_STRING)])' ; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])' ; \
	} > $@

test_library: package.m4 test_library.at test_macros.at

test_manpages: package.m4 test_manpages.at

test_python_module: package.m4 test_python_module.at

EXTRA_DIST = \
	$(check_AUTOTESTS:=.at) \
	$(check_PYTHON_SCRIPTS) \
	package.m4 \
	test_macros.at

CLEANFILES = \
	$(check_AUTOTESTS) \
	*.exe \
	*.tmp

DISTCLEANFILES = \
	*.log \
	atconfig \
	Makefile \
	Makefile.in

