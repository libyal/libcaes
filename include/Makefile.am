include_HEADERS = \
	libcaes.h

pkginclude_HEADERS = \
	libcaes/definitions.h \
	libcaes/error.h \
	libcaes/extern.h \
	libcaes/features.h \
	libcaes/types.h

EXTRA_DIST = \
	libcaes.h.in \
	libcaes/definitions.h.in \
	libcaes/features.h.in \
	libcaes/types.h.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	-rm -f libcaes.h
	-rm -f libcaes/definitions.h
	-rm -f libcaes/features.h
	-rm -f libcaes/types.h
	-rm -f Makefile

