MSVSCPP_FILES = \
	caes_test_crypt_cbc/caes_test_crypt_cbc.vcproj \
	caes_test_crypt_ccm/caes_test_crypt_ccm.vcproj \
	caes_test_crypt_cfb/caes_test_crypt_cfb.vcproj \
	caes_test_crypt_ecb/caes_test_crypt_ecb.vcproj \
	caes_test_crypt_xts/caes_test_crypt_xts.vcproj \
	libcaes/libcaes.vcproj \
	libcerror/libcerror.vcproj \
	libcstring/libcstring.vcproj \
	libcaes.sln

SCRIPT_FILES = \
	scripts/vs2008_x64.sh \
	scripts/vs2008_x64_sln.sed \
	scripts/vs2008_x64_vcproj.sed \
	scripts/vs2010_x64.sh \
	scripts/vs2010_x64_sln.sed \
	scripts/vs2010_x64_vcxproj.sed

EXTRA_DIST = \
	$(MSVSCPP_FILES) \
	$(SCRIPT_FILES)

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

