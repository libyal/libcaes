# Note that we cannot use: AUTOMAKE_OPTIONS = subdir-objects
# subdir-objects will compile the source files to a single version of Python.
# Since subdir-objects is being deprecated we copy the source files instead.
am__installdirs = "$(DESTDIR)$(pyexecdir3)"
pyexecdir = $(pyexecdir3)

if HAVE_PYTHON3
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@

am_pycaes_la_rpath = -rpath $(pyexecdir3)

BUILT_SOURCES = \
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

pyexec_LTLIBRARIES = pycaes.la

nodist_pycaes_la_SOURCES = $(BUILT_SOURCES)

pycaes_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libcaes/libcaes.la

pycaes_la_CPPFLAGS = $(PYTHON3_CPPFLAGS)
pycaes_la_LDFLAGS  = -module -avoid-version $(PYTHON3_LDFLAGS)

$(BUILT_SOURCES):
	/bin/cp -f $(top_srcdir)/pycaes/$@ $@

endif

MAINTAINERCLEANFILES = \
	Makefile.in

clean-local:
	/bin/rm -f pycaes*.[ch]

distclean: clean
	/bin/rm -f Makefile

