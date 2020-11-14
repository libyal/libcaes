if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common

bin_PROGRAMS = \
	crypt_cbc_fuzzer \
	crypt_ccm_fuzzer \
	crypt_ecb_fuzzer \
	crypt_xts_fuzzer

crypt_cbc_fuzzer_SOURCES = \
	crypt_cbc_fuzzer.cc \
	ossfuzz_libcaes.h

crypt_cbc_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libcaes/libcaes.la

crypt_ccm_fuzzer_SOURCES = \
	crypt_ccm_fuzzer.cc \
	ossfuzz_libcaes.h

crypt_ccm_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libcaes/libcaes.la

crypt_ecb_fuzzer_SOURCES = \
	crypt_ecb_fuzzer.cc \
	ossfuzz_libcaes.h

crypt_ecb_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libcaes/libcaes.la

crypt_xts_fuzzer_SOURCES = \
	crypt_xts_fuzzer.cc \
	ossfuzz_libcaes.h

crypt_xts_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libcaes/libcaes.la
endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on crypt_cbc_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_cbc_fuzzer_SOURCES)
	@echo "Running splint on crypt_ccm_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_ccm_fuzzer_SOURCES)
	@echo "Running splint on crypt_ecb_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_ecb_fuzzer_SOURCES)
	@echo "Running splint on crypt_xts_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_xts_fuzzer_SOURCES)

