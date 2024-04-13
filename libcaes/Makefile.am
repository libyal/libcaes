AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@LIBCAES_DLL_EXPORT@

lib_LTLIBRARIES = libcaes.la

libcaes_la_SOURCES = \
	libcaes.c \
	libcaes_context.c libcaes_context.h \
	libcaes_definitions.h \
	libcaes_extern.h \
	libcaes_error.c libcaes_error.h \
	libcaes_libcerror.h \
	libcaes_support.c libcaes_support.h \
	libcaes_tweaked_context.c libcaes_tweaked_context.h \
	libcaes_types.h \
	libcaes_unused.h

libcaes_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	@LIBCRYPTO_LIBADD@ \
	@LIBDL_LIBADD@

libcaes_la_LDFLAGS = -no-undefined -version-info 1:0:0

EXTRA_DIST = \
	libcaes_definitions.h.in \
	libcaes.rc \
	libcaes.rc.in

DISTCLEANFILES = \
	libcaes_definitions.h \
	libcaes.rc \
	Makefile \
	Makefile.in

sources-local: $(BUILT_SOURCES)

splint-local:
	@echo "Running splint on libcaes ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(libcaes_la_SOURCES)

