/* settings.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */

/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */

#ifndef WOLF_CRYPT_SETTINGS_H
#define WOLF_CRYPT_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Uncomment next line if building for Freescale KSDK Bare Metal */
/* #define FREESCALE_KSDK_BM */

/* Uncomment next line if building for Freescale KSDK FreeRTOS */
/* #define FSL_RTOS_FREE_RTOS */

/* Redefine baremetal macro for MCUXpresso NPW compatibility */
#if defined(FSL_RTOS_BM) && !defined(FREESCALE_KSDK_BM)
#define FREESCALE_KSDK_BM
#endif

/* Note in Freescale KSDK examples either macro is defined in the build project settings (as C preprocessor macro) */
#if !defined(FREESCALE_KSDK_BM) && !defined(FSL_RTOS_FREE_RTOS)
#error "Please define either FREESCALE_KSDK_BM or FSL_RTOS_FREE_RTOS for your project!"
#endif

/* Uncomment next line if using Max Strength build */
/* #define WOLFSSL_MAX_STRENGTH */

/* Uncomment next line to enable deprecated less secure static DH suites */
/* #define WOLFSSL_STATIC_DH */

/* Uncomment next line to enable deprecated less secure static RSA suites */
/* #define WOLFSSL_STATIC_RSA */

/* Uncomment next line to enable asynchronous crypto WC_PENDING_E */
/* #define WOLFSSL_ASYNC_CRYPT */

#include <wolfssl/wolfcrypt/visibility.h>

#ifdef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif

/* make sure old RNG name is used with CTaoCrypt FIPS */
#ifdef HAVE_FIPS
#define WC_RNG RNG
/* blinding adds API not available yet in FIPS mode */
#undef WC_RSA_BLINDING
#endif

#ifdef FSL_RTOS_FREE_RTOS
#define FREESCALE_COMMON
/* Allows use of DH with fixed points if uncommented and NO_DH is removed */
/* WOLFSSL_DH_CONST */
/* Allows use of DH with fixed points if uncommented and NO_DH is removed */
/* WOLFSSL_DH_CONST */
/* Allows use of DH with fixed points if uncommented and NO_DH is removed */
/* WOLFSSL_DH_CONST */
#define NO_FILESYSTEM
#define WOLFSSL_CRYPT_HW_MUTEX 1

#if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY)
#define XMALLOC(s, h, type) pvPortMalloc((s))
#define XFREE(p, h, type) vPortFree((p))
#endif

/* #define USER_TICKS */
#define WOLFSSL_LWIP
#define FREERTOS_TCP

#define FREESCALE_FREE_RTOS
#define FREERTOS_SOCKET_ERROR (-1)
#define FREERTOS_EWOULDBLOCK (-2)
#define FREERTOS_EINVAL (-4)
#define FREERTOS_EADDRNOTAVAIL (-5)
#define FREERTOS_EADDRINUSE (-6)
#define FREERTOS_ENOBUFS (-7)
#define FREERTOS_ENOPROTOOPT (-8)

#define MQX_FILE_PTR FILE *
#define IO_SEEK_SET SEEK_SET
#define IO_SEEK_END SEEK_END
#endif

#ifdef FREESCALE_KSDK_BM
#define FREESCALE_COMMON
#define WOLFSSL_USER_IO
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define USER_TICKS
#endif

#ifdef FREESCALE_COMMON
#define SIZEOF_LONG_LONG 8

/* disable features */
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_RABBIT
#define NO_WOLFSSL_DIR

/* enable features */
#define USE_FAST_MATH

#define USE_CERT_BUFFERS_2048
#define BENCH_EMBEDDED

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define ALT_ECC_SIZE

#define HAVE_ECC
#define HAVE_AESCCM
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER (1)
#define WOLFSSL_AES_DIRECT (1)
#define NO_RC4

#include "fsl_common.h"

/* random seed */
#define NO_OLD_RNGNAME
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
#define FREESCALE_KSDK_2_0_TRNG
#elif defined(FSL_FEATURE_SOC_RNG_COUNT) && (FSL_FEATURE_SOC_RNG_COUNT > 0)
#define FREESCALE_KSDK_2_0_RNGA
#elif defined(FSL_FEATURE_SOC_LPC_RNG_COUNT) && (FSL_FEATURE_SOC_LPC_RNG_COUNT > 0)
#define FREESCALE_KSDK_2_0_LPC_RNG
#elif !defined(FREESCALE_KSDK_BM) && !defined(FREESCALE_FREE_RTOS) && !defined(FREESCALE_KSDK_FREERTOS)
#define FREESCALE_RNGA
#define RNGA_INSTANCE (0)
/* defaulting to K70 RNGA, user should change if different */
/* #define FREESCALE_K53_RNGB */
#define FREESCALE_K70_RNGA
#endif

/* HW crypto */
/* automatic enable based on chip feature */
/* If case manual selection is required, for example for benchmarking purposes,
 * just define FREESCALE_USE_MMCAU, FREESCALE_USE_LTC, FREESCALE_USE_LPC_AES
 * or FREESCALE_USE_LPC_SHA or none of these macros (for software only).
 * All can be enabled simultaneously as LTC has priority over MMCAU in source code.
 */
/* #define FSL_HW_CRYPTO_MANUAL_SELECTION */
#ifndef FSL_HW_CRYPTO_MANUAL_SELECTION
#if defined(FSL_FEATURE_SOC_MMCAU_COUNT) && FSL_FEATURE_SOC_MMCAU_COUNT
#define FREESCALE_USE_MMCAU
#endif

#if defined(FSL_FEATURE_SOC_CAAM_COUNT) && FSL_FEATURE_SOC_CAAM_COUNT  && defined(CRYPTO_USE_DRIVER_CAAM)
#define FREESCALE_USE_CAAM
#endif

#if defined(FSL_FEATURE_SOC_CAU3_COUNT) && FSL_FEATURE_SOC_CAU3_COUNT
#define FREESCALE_USE_CAU3
#endif

#if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
#define FREESCALE_USE_LTC
#endif

#if defined(FSL_FEATURE_SOC_AES_COUNT) && FSL_FEATURE_SOC_AES_COUNT
#define FREESCALE_USE_LPC_AES
#endif

#if defined(FSL_FEATURE_SOC_SHA_COUNT) && FSL_FEATURE_SOC_SHA_COUNT
#define FREESCALE_USE_LPC_SHA
#endif

#if defined(FSL_FEATURE_SOC_DCP_COUNT) && FSL_FEATURE_SOC_DCP_COUNT
#define FREESCALE_USE_DCP
#endif
#else
/* #define FREESCALE_USE_MMCAU */
/* #define FREESCALE_USE_LTC */
/* #define FREESCALE_USE_LPC_AES */
/* #define FREESCALE_USE_LPC_SHA */
#endif
#endif

#if defined(FREESCALE_USE_MMCAU)
/* AES and DES */
#define FREESCALE_MMCAU
/* MD5, SHA-1 and SHA-256 */
#define FREESCALE_MMCAU_SHA
#endif /* FREESCALE_USE_MMCAU */

#if defined(FREESCALE_USE_CAAM)

#define FREESCALE_CAAM

#define FREESCALE_CAAM_SHA
#define FREESCALE_CAAM_SHA256
#define FREESCALE_CAAM_AES
#define FREESCALE_CAAM_DES
#define FREESCALE_CAAM_DES3
#define FREESCALE_CAAM_ECC

/* SHA alternate functions */
#define FREESCALE_SHA1_ALT
#define FREESCALE_SHA256_ALT

/* AES alternate functions */
#define FREESCALE_AES_SETKEY_ALT
#define FREESCALE_AES_ALT
#define FREESCALE_AES_CBC_ALT
#define FREESCALE_AES_CTR_ALT
#define FREESCALE_AES_GCM_ALT
#define FREESCALE_AES_CCM_ALT

/* DES alternate functions */
#define FREESCALE_DES_SETKEY_ALT
#define FREESCALE_DES3_SETKEY_ALT
#define FREESCALE_DES_CBC_ALT
#define FREESCALE_DES3_CBC_ALT

/* Alternate structs */
#define FREESCALE_SHA1_STRUCT_ALT
#define FREESCALE_SHA256_STRUCT_ALT

/* CAAM PKHA settings */
#define USE_FAST_MATH
#define FREESCALE_TFM_ALT
#define FREESCALE_CAAM_TFM
#define CAAM_MAX_INT_BYTES (512)

/* CAAM ECC settings */
#ifdef HAVE_ECC
#ifndef ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT (1)
#endif
#define ECC_USER_CURVES
#define HAVE_ECC192 (1)
#define HAVE_ECC224 (1)
#define HAVE_ECC384 (1)
#define CAAM_MAX_ECC_BITS (384)
#define FREESCALE_ECC_ALT
#endif /* HAVE_ECC */
#endif /* FREESCALE_USE_CAAM */

#if defined(FREESCALE_USE_CAU3)

#define FREESCALE_CAU3
#define FREESCALE_CAU3_COMPLETION_SIGNAL kCAU3_TaskDoneEvent

#define FREESCALE_CAU3_SHA
#define FREESCALE_CAU3_SHA256
#define FREESCALE_CAU3_DES3
#define FREESCALE_CAU3_AES
#define FREESCALE_CAU3_ECC

/* SHA alternate functions */
#define FREESCALE_SHA1_ALT
#define FREESCALE_SHA256_ALT

/* DES alternate functions */
#define FREESCALE_DES3_SETKEY_ALT
#define FREESCALE_DES3_CBC_ALT

/* AES alternate functions */
#define FREESCALE_AES_ALT
#define FREESCALE_AES_SETKEY_ALT

/* Alternate structs */
#define FREESCALE_SHA1_STRUCT_ALT
#define FREESCALE_SHA256_STRUCT_ALT

#define FREESCALE_AES_NO_192

/* CAU3 PKHA settings */
#define USE_FAST_MATH
#define FREESCALE_TFM_ALT
#define FREESCALE_CAU3_TFM
#define CAU3_MAX_INT_BYTES (512)

/* CAU3 ECC settings */
#ifdef HAVE_ECC
#define FREESCALE_ECC_ALT
#ifndef ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT (1)
#endif
#define ECC_USER_CURVES
#define HAVE_ECC192 (1)
#define HAVE_ECC224 (1)
#define HAVE_ECC384 (1)
#define CAU3_MAX_ECC_BITS (512)
#endif

#endif /* FREESCALE_USE_CAU3 */

#if defined(FREESCALE_USE_DCP)

#define FREESCALE_DCP

#define FREESCALE_DCP_SHA
#define FREESCALE_DCP_SHA256
#define FREESCALE_DCP_AES

/* SHA alternate functions */
#define FREESCALE_SHA1_ALT
#define FREESCALE_SHA256_ALT

/* AES alternate functions */
#define FREESCALE_AES_ALT
#define FREESCALE_AES_CBC_ALT
#define FREESCALE_AES_SETKEY_ALT

/* Alternate structs */
#define FREESCALE_SHA1_STRUCT_ALT
#define FREESCALE_SHA256_STRUCT_ALT

#define FREESCALE_AES_NO_192
#define FREESCALE_AES_NO_256

#endif /* FREESCALE_USE_DCP */

#if defined(FREESCALE_USE_LTC)
#if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
#define FREESCALE_LTC
#define LTC_BASE LTC0

#if !(defined(FSL_FEATURE_LTC_HAS_AES192) && FSL_FEATURE_LTC_HAS_AES192)
#define FREESCALE_AES_NO_192
#endif

#if !(defined(FSL_FEATURE_LTC_HAS_AES256) && FSL_FEATURE_LTC_HAS_AES256)
#define FREESCALE_AES_NO_256
#endif

#if defined(FSL_FEATURE_LTC_HAS_DES) && FSL_FEATURE_LTC_HAS_DES
#define FREESCALE_LTC_DES
#endif

#if defined(FSL_FEATURE_LTC_HAS_GCM) && FSL_FEATURE_LTC_HAS_GCM
#define FREESCALE_LTC_AES_GCM
#endif

#if defined(FSL_FEATURE_LTC_HAS_SHA) && FSL_FEATURE_LTC_HAS_SHA
#define FREESCALE_LTC_SHA
#endif

#if defined(FSL_FEATURE_LTC_HAS_PKHA) && FSL_FEATURE_LTC_HAS_PKHA
#define FREESCALE_LTC_ECC
#define FREESCALE_TFM_ALT
#define FREESCALE_LTC_TFM
/* the LTC PKHA hardware limit is 2048 bits (256 bytes) for integer arithmetic.
   the LTC_MAX_INT_BYTES defines the size of local variables that hold big integers. */
#define LTC_MAX_INT_BYTES (256)

/* This FREESCALE_LTC_TFM_RSA_4096_ENABLE macro can be defined.
 * In such a case both software and hardware algorithm
 * for TFM is linked in. The decision for which algorithm is used is determined at runtime
 * from size of inputs. If inputs and result can fit into LTC (see LTC_MAX_INT_BYTES)
 * then we call hardware algorithm, otherwise we call software algorithm.
 *
 * Chinese reminder theorem is used to break RSA 4096 exponentiations (private key)
 * into several computations with 2048-bit modulus and exponents.
 */
/* #define FREESCALE_LTC_TFM_RSA_4096_ENABLE */

/* ECC-384, ECC-256, ECC-224 and ECC-192 have been enabled with LTC PKHA acceleration */
#ifdef HAVE_ECC
#define FREESCALE_ECC_ALT
#ifndef ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT (1)
#endif
#define ECC_USER_CURVES
#define HAVE_ECC192 (1)
#define HAVE_ECC224 (1)
#define HAVE_ECC384 (1)
#define HAVE_CURVE25519

/* the LTC PKHA hardware limit is 512 bits (64 bytes) for ECC.
   the LTC_MAX_ECC_BITS defines the size of local variables that hold ECC parameters and point coordinates */
#define LTC_MAX_ECC_BITS (384)

#define HAVE_ED25519
#define WOLFSSL_SHA512
#endif
#endif
#endif
#endif /* FREESCALE_USE_LTC */

#if defined(FREESCALE_USE_LPC_AES)
#define FREESCALE_LPC_AES

#if defined(FSL_FEATURE_SOC_AES_COUNT) && FSL_FEATURE_SOC_AES_COUNT
#define AES_BASE AES0
#define FREESCALE_LPC_AES_GCM
#endif
#endif /* FREESCALE_USE_LPC_AES */

#if defined(FREESCALE_USE_LPC_SHA)
#define FREESCALE_LPC_SHA

#if defined(FSL_FEATURE_SOC_SHA_COUNT) && FSL_FEATURE_SOC_SHA_COUNT
#define SHA_BASE SHA0
#endif
#endif /* FREESCALE_USE_LPC_SHA */

#ifdef FREESCALE_LTC_TFM_RSA_4096_ENABLE
#undef USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_4096
#define FP_MAX_BITS (8192)
#define NO_DH
#define NO_DSA
#endif

#if !defined(XMALLOC_USER) && !defined(MICRIUM_MALLOC) && !defined(WOLFSSL_LEANPSK) && !defined(NO_WOLFSSL_MEMORY)
#define USE_WOLFSSL_MEMORY
#endif

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS)
#undef KEEP_PEER_CERT
#define KEEP_PEER_CERT
#endif

/* FreeScale MMCAU hardware crypto has 4 byte alignment.
   However, fsl_mmcau.h gives API with no alignment requirements (4 byte alignment is managed internally by fsl_mmcau.c)
   */
#ifdef FREESCALE_MMCAU
#define WOLFSSL_MMCAU_ALIGNMENT 0
#endif

/* if LTC has AES engine but doesn't have GCM, use software with LTC AES ECB mode */
#if defined(FREESCALE_USE_LTC) && !defined(FREESCALE_LTC_AES_GCM)
#define GCM_TABLE
#endif

/* if using hardware crypto and have alignment requirements, specify the
   requirement here.  The record header of SSL/TLS will prevent easy alignment.
   This hint tries to help as much as possible.  */
#ifndef WOLFSSL_GENERAL_ALIGNMENT
#ifdef WOLFSSL_AESNI
#define WOLFSSL_GENERAL_ALIGNMENT 16
#elif defined(XSTREAM_ALIGN)
#define WOLFSSL_GENERAL_ALIGNMENT 4
#elif defined(FREESCALE_MMCAU)
#define WOLFSSL_GENERAL_ALIGNMENT WOLFSSL_MMCAU_ALIGNMENT
#else
#define WOLFSSL_GENERAL_ALIGNMENT 0
#endif
#endif

#if defined(WOLFSSL_GENERAL_ALIGNMENT) && (WOLFSSL_GENERAL_ALIGNMENT > 0)
#if defined(_MSC_VER)
#define XGEN_ALIGN __declspec(align(WOLFSSL_GENERAL_ALIGNMENT))
#elif defined(__GNUC__)
#define XGEN_ALIGN __attribute__((aligned(WOLFSSL_GENERAL_ALIGNMENT)))
#else
#define XGEN_ALIGN
#endif
#else
#define XGEN_ALIGN
#endif

/* user can specify what curves they want with ECC_USER_CURVES otherwise
 * all curves are on by default for now */
#ifndef ECC_USER_CURVES
#ifndef HAVE_ALL_CURVES
#define HAVE_ALL_CURVES
#endif
#endif

/* ECC Configs */
#ifdef HAVE_ECC
/* By default enable Sign, Verify, DHE, Key Import and Key Export unless explicitly disabled */
#ifndef NO_ECC_SIGN
#undef HAVE_ECC_SIGN
#define HAVE_ECC_SIGN
#endif
#ifndef NO_ECC_VERIFY
#undef HAVE_ECC_VERIFY
#define HAVE_ECC_VERIFY
#endif
#ifndef NO_ECC_DHE
#undef HAVE_ECC_DHE
#define HAVE_ECC_DHE
#endif
#ifndef NO_ECC_KEY_IMPORT
#undef HAVE_ECC_KEY_IMPORT
#define HAVE_ECC_KEY_IMPORT
#endif
#ifndef NO_ECC_KEY_EXPORT
#undef HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_EXPORT
#endif
#endif /* HAVE_ECC */

/* Curve255519 Configs */
#ifdef HAVE_CURVE25519
/* By default enable shared secret, key export and import */
#ifndef NO_CURVE25519_SHARED_SECRET
#undef HAVE_CURVE25519_SHARED_SECRET
#define HAVE_CURVE25519_SHARED_SECRET
#endif
#ifndef NO_CURVE25519_KEY_EXPORT
#undef HAVE_CURVE25519_KEY_EXPORT
#define HAVE_CURVE25519_KEY_EXPORT
#endif
#ifndef NO_CURVE25519_KEY_IMPORT
#undef HAVE_CURVE25519_KEY_IMPORT
#define HAVE_CURVE25519_KEY_IMPORT
#endif
#endif /* HAVE_CURVE25519 */

/* Ed255519 Configs */
#ifdef HAVE_ED25519
/* By default enable sign, verify, key export and import */
#ifndef NO_ED25519_SIGN
#undef HAVE_ED25519_SIGN
#define HAVE_ED25519_SIGN
#endif
#ifndef NO_ED25519_VERIFY
#undef HAVE_ED25519_VERIFY
#define HAVE_ED25519_VERIFY
#endif
#ifndef NO_ED25519_KEY_EXPORT
#undef HAVE_ED25519_KEY_EXPORT
#define HAVE_ED25519_KEY_EXPORT
#endif
#ifndef NO_ED25519_KEY_IMPORT
#undef HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_IMPORT
#endif
#endif /* HAVE_ED25519 */

/* AES Config */
#ifndef NO_AES
/* By default enable all AES key sizes, decryption and CBC */
#ifndef AES_MAX_KEY_SIZE
#undef AES_MAX_KEY_SIZE
#define AES_MAX_KEY_SIZE 256
#endif
#ifndef NO_AES_DECRYPT
#undef HAVE_AES_DECRYPT
#define HAVE_AES_DECRYPT
#endif
#ifndef NO_AES_CBC
#undef HAVE_AES_CBC
#define HAVE_AES_CBC
#else
#ifndef WOLFCRYPT_ONLY
#error "AES CBC is required for TLS and can only be disabled for WOLFCRYPT_ONLY builds"
#endif
#endif
#endif

/* If using the max strength build, ensure OLD TLS is disabled. */
#ifdef WOLFSSL_MAX_STRENGTH
#undef NO_OLD_TLS
#define NO_OLD_TLS
#endif

/* If not forcing ARC4 as the DRBG or using custom RNG block gen, enable Hash_DRBG */
#undef HAVE_HASHDRBG
#if !defined(WOLFSSL_FORCE_RC4_DRBG) && !defined(CUSTOM_RAND_GENERATE_BLOCK)
#define HAVE_HASHDRBG
#endif

/* Decode Public Key extras on by default, user can turn off with
 * WOLFSSL_NO_DECODE_EXTRA */
#ifndef WOLFSSL_NO_DECODE_EXTRA
#ifndef RSA_DECODE_EXTRA
#define RSA_DECODE_EXTRA
#endif
#ifndef ECC_DECODE_EXTRA
#define ECC_DECODE_EXTRA
#endif
#endif

/* C Sharp wrapper defines */
#ifdef HAVE_CSHARP
#ifndef WOLFSSL_DTLS
#define WOLFSSL_DTLS
#endif
#undef NO_PSK
#undef NO_SHA256
#undef NO_DH
#endif

/* Asynchronous Crypto */
#ifdef WOLFSSL_ASYNC_CRYPT
/* Make sure wolf events are enabled */
#undef HAVE_WOLF_EVENT
#define HAVE_WOLF_EVENT
#else
#ifdef WOLFSSL_ASYNC_CRYPT_TEST
#error Must have WOLFSSL_ASYNC_CRYPT enabled with WOLFSSL_ASYNC_CRYPT_TEST
#endif
#endif /* WOLFSSL_ASYNC_CRYPT */

/* leantls checks */
#ifdef WOLFSSL_LEANTLS
#ifndef HAVE_ECC
#error leantls build needs ECC
#endif
#endif /* WOLFSSL_LEANTLS*/

/* restriction with static memory */
#ifdef WOLFSSL_STATIC_MEMORY
#ifndef USE_FAST_MATH
#error static memory requires fast math please define USE_FAST_MATH
#endif
#ifdef WOLFSSL_SMALL_STACK
#error static memory does not support small stack please undefine
#endif
#endif /* WOLFSSL_STATIC_MEMORY */

/* Place any other flags or defines here */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
