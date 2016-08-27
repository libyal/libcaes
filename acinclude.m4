dnl Functions for libcaes
dnl
dnl Version: 20160827

dnl Function to detect if libcaes dependencies are available
AC_DEFUN([AX_LIBCAES_CHECK_LOCAL],
 [dnl Check for Windows crypto API support
 AX_WINCRYPT_CHECK_LIB

 AS_IF(
  [test "x$ac_cv_wincrypt" != xno],
  [ac_cv_libcaes_aes=$ac_cv_wincrypt],
  [ac_cv_libcaes_aes=no])
 
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

