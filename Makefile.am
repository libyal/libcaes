ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	include \
	common \
	libcerror \
	libcaes \
	pycaes \
	pycaes-python2 \
	pycaes-python3 \
	po \
	manuals \
	tests \
	msvscpp

DPKG_FILES = \
	dpkg/changelog \
	dpkg/changelog.in \
	dpkg/compat \
	dpkg/control \
	dpkg/copyright \
	dpkg/copyright.in \
	dpkg/rules \
	dpkg/libcaes.docs \
	dpkg/libcaes-dev.docs \
	dpkg/libcaes-python.docs \
	dpkg/libcaes-python3.docs \
	dpkg/source/format

GETTEXT_FILES = \
	config.rpath \
	po/Makevars.in

PKGCONFIG_FILES = \
	libcaes.pc.in

SETUP_PY_FILES = \
	setup.py

SPEC_FILES = \
	libcaes.spec \
	libcaes.spec.in

EXTRA_DIST = \
	$(DPKG_FILES) \
	$(GETTEXT_FILES) \
	$(PKGCONFIG_FILES) \
	$(SETUP_PY_FILES) \
	$(SPEC_FILES)

MAINTAINERCLEANFILES = \
	Makefile.in

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = \
	libcaes.pc

libtool: @LIBTOOL_DEPS@
	cd $(srcdir) && $(SHELL) ./config.status --recheck

lib: library

library:
	(cd $(srcdir)/common && $(MAKE) $(AM_MAKEFLAGS))
	(cd $(srcdir)/libcerror && $(MAKE) $(AM_MAKEFLAGS))
	(cd $(srcdir)/libcaes && $(MAKE) $(AM_MAKEFLAGS))
	(cd $(srcdir)/po && $(MAKE) $(AM_MAKEFLAGS))

distclean: clean
	/bin/rm -f Makefile
	/bin/rm -f config.status
	/bin/rm -f config.cache
	/bin/rm -f config.log
	/bin/rm -f libcaes.pc
	/bin/rm -f libcaes.spec
	@for dir in ${subdirs}; do \
		(cd $$dir && $(MAKE) distclean) \
		|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

splint:
	(cd $(srcdir)/libcerror && $(MAKE) splint $(AM_MAKEFLAGS))
	(cd $(srcdir)/libcaes && $(MAKE) splint $(AM_MAKEFLAGS))
	(cd $(srcdir)/pycaes && $(MAKE) splint $(AM_MAKEFLAGS))
	(cd $(srcdir)/po && $(MAKE) splint $(AM_MAKEFLAGS))
	(cd $(srcdir)/tests && $(MAKE) splint $(AM_MAKEFLAGS))

