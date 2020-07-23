dnl Checks for required headers and functions
dnl
dnl Version: 20190308

dnl Function to detect if libcaes dependencies are available
AC_DEFUN([AX_LIBCAES_CHECK_LOCAL],
  [dnl Check for libcrypto (openssl) support
  AX_LIBCRYPTO_CHECK_ENABLE

  AS_IF(
    [test "x$ac_cv_libcrypto" != xno],
    [AX_LIBCRYPTO_CHECK_AES
    AX_LIBCRYPTO_CHECK_AES_XTS])

  dnl Fallback to local versions if necessary
  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_aes_cbc" = xno],
    [ac_cv_libcaes_aes_cbc=local],
    [ac_cv_libcaes_aes_cbc=$ac_cv_libcrypto_aes_cbc])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_aes_ecb" = xno],
    [ac_cv_libcaes_aes_ecb=local],
    [ac_cv_libcaes_aes_ecb=$ac_cv_libcrypto_aes_ecb])

  AS_IF(
    [test "x$ac_cv_libcrypto" = xno || test "x$ac_cv_libcrypto_aes_xts" = xno],
    [ac_cv_libcaes_aes_xts=local],
    [ac_cv_libcaes_aes_xts=$ac_cv_libcrypto_aes_xts])
  ])

dnl Function to check if DLL support is needed
AC_DEFUN([AX_LIBCAES_CHECK_DLL_SUPPORT],
  [AS_IF(
    [test "x$enable_shared" = xyes],
    [AS_CASE(
      [$host],
      [*cygwin* | *mingw* | *msys*],
      [AC_DEFINE(
        [HAVE_DLLMAIN],
        [1],
        [Define to 1 to enable the DllMain function.])
      AC_SUBST(
        [HAVE_DLLMAIN],
        [1])

      AC_SUBST(
        [LIBCAES_DLL_EXPORT],
        ["-DLIBCAES_DLL_EXPORT"])

      AC_SUBST(
        [LIBCAES_DLL_IMPORT],
        ["-DLIBCAES_DLL_IMPORT"])
      ])
    ])
  ])

