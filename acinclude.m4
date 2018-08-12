dnl Checks for required headers and functions
dnl
dnl Version: 20180812

dnl Function to detect if libcaes dependencies are available
AC_DEFUN([AX_LIBCAES_CHECK_LOCAL],
  [ac_cv_libcaes_aes=no

  dnl Check for Windows crypto API support
  AS_IF(
    [test "x$ac_cv_enable_winapi" = xyes],
    [ac_cv_libcaes_aes=libadvapi32])

  dnl Check for libcrypto (openssl) support
  AS_IF(
    [test "x$ac_cv_libcaes_aes" = xno],
    [AX_LIBCRYPTO_CHECK_ENABLE

    AS_IF(
      [test "x$ac_cv_libcrypto" != xno],
      [AX_LIBCRYPTO_CHECK_AES

      ac_cv_libcaes_aes=$ac_cv_libcrypto_aes])
    ])

  dnl Fallback to local versions if necessary
  AS_IF(
    [test "x$ac_cv_libcaes_aes" = xno],
    [ac_cv_libcaes_aes=local])
  ])

