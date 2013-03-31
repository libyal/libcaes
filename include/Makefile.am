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
	/bin/rm -f libcaes.h
	/bin/rm -f libcaes/definitions.h
	/bin/rm -f libcaes/features.h
	/bin/rm -f libcaes/types.h
	/bin/rm -f Makefile

