if HAVE_PYTHON
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@

pyexec_LTLIBRARIES = pycaes.la

pycaes_la_SOURCES = \
	pycaes.c pycaes.h \
	pycaes_context.c pycaes_context.h \
	pycaes_crypt.c pycaes_crypt.h \
	pycaes_crypt_modes.c pycaes_crypt_modes.h \
	pycaes_error.c pycaes_error.h \
	pycaes_libcaes.h \
	pycaes_libcerror.h \
	pycaes_python.h \
	pycaes_tweaked_context.c pycaes_tweaked_context.h \
	pycaes_unused.h

pycaes_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

pycaes_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
pycaes_la_LDFLAGS  = -module -avoid-version $(PYTHON_LDFLAGS)

endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

