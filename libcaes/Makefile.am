AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@

lib_LTLIBRARIES = libcaes.la

libcaes_la_SOURCES = \
	libcaes.c \
	libcaes_context.c libcaes_context.h \
	libcaes_crypt.c libcaes_crypt.h \
	libcaes_definitions.h \
	libcaes_extern.h \
	libcaes_error.c libcaes_error.h \
	libcaes_key.c libcaes_key.h \
	libcaes_libcerror.h \
	libcaes_libcstring.h \
	libcaes_support.c libcaes_support.h \
	libcaes_tweaked_context.c libcaes_tweaked_context.h \
	libcaes_types.h \
	libcaes_unused.h

libcaes_la_LIBADD = \
	@LIBCSTRING_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBCRYPTO_LIBADD@ \
	@LIBDL_LIBADD@

libcaes_la_LDFLAGS = -no-undefined -version-info 1:0:0

EXTRA_DIST = \
	libcaes_definitions.h.in \
	libcaes.rc \
	libcaes.rc.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f libcaes_definitions.h
	/bin/rm -f libcaes.rc
	/bin/rm -f Makefile

splint:
	@echo "Running splint on libcaes ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(libcaes_la_SOURCES)

