/* crypto/err/err_all.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif
#include <openssl/buffer.h>
#include <openssl/bio.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_ECDSA
# include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
# include <openssl/ecdh.h>
#endif
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/dso.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/ui.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif
#include <openssl/ts.h>
#ifndef OPENSSL_NO_CMS
# include <openssl/cms.h>
#endif
#ifndef OPENSSL_NO_JPAKE
# include <openssl/jpake.h>
#endif
# ifndef OPENSSL_NO_HSS
# include <openssl/hss.h>
# endif
# ifndef OPENSSL_NO_XMSS
# include <openssl/xmss.h>
# endif
# ifndef OPENSSL_NO_XMSSMT
# include <openssl/xmssmt.h>
# endif
# ifndef OPENSSL_NO_DILITHIUM
# include <openssl/dilithium.h>
# endif
# ifndef OPENSSL_NO_SPHINCS
# include <openssl/sphincs.h>
# endif
# ifndef OPENSSL_NO_FRODODH
# include <openssl/frododh.h>
# endif
# ifndef OPENSSL_NO_SAMWISE
# include <openssl/samwise.h>
# endif
# ifndef OPENSSL_NO_RAINBOW
# include <openssl/rainbow.h>
# endif
# if !defined(OPENSSL_NO_NHDH)
# include <openssl/nhdh.h>
# endif
# ifndef OPENSSL_NO_SIDH
# include <openssl/sidh.h>
# endif
# ifndef OPENSSL_NO_CMC
# include <openssl/cmc.h>
# endif
# ifndef OPENSSL_NO_NTRUP
# include <openssl/ntrup.h>
# endif
# ifndef OPENSSL_NO_KYBER
# include <openssl/kyber.h>
# endif
# ifndef OPENSSL_NO_SIKE
# include <openssl/sike.h>
# endif
# ifndef OPENSSL_NO_FRODOKEM
# include <openssl/frodokem.h>
# endif

void ERR_load_crypto_strings(void)
{
#ifndef OPENSSL_NO_ERR
    ERR_load_ERR_strings();     /* include error strings for SYSerr */
    ERR_load_BN_strings();
# ifndef OPENSSL_NO_RSA
    ERR_load_RSA_strings();
# endif
# ifndef OPENSSL_NO_DH
    ERR_load_DH_strings();
# endif
    ERR_load_EVP_strings();
    ERR_load_BUF_strings();
    ERR_load_OBJ_strings();
    ERR_load_PEM_strings();
# ifndef OPENSSL_NO_DSA
    ERR_load_DSA_strings();
# endif
    ERR_load_X509_strings();
    ERR_load_ASN1_strings();
    ERR_load_CONF_strings();
    ERR_load_CRYPTO_strings();
# ifndef OPENSSL_NO_COMP
    ERR_load_COMP_strings();
# endif
# ifndef OPENSSL_NO_EC
    ERR_load_EC_strings();
# endif
# ifndef OPENSSL_NO_ECDSA
    ERR_load_ECDSA_strings();
# endif
# ifndef OPENSSL_NO_ECDH
    ERR_load_ECDH_strings();
# endif
    /* skip ERR_load_SSL_strings() because it is not in this library */
    ERR_load_BIO_strings();
    ERR_load_PKCS7_strings();
    ERR_load_X509V3_strings();
    ERR_load_PKCS12_strings();
    ERR_load_RAND_strings();
    ERR_load_DSO_strings();
    ERR_load_TS_strings();
# ifndef OPENSSL_NO_ENGINE
    ERR_load_ENGINE_strings();
# endif
    ERR_load_OCSP_strings();
    ERR_load_UI_strings();
# ifdef OPENSSL_FIPS
    ERR_load_FIPS_strings();
# endif
# ifndef OPENSSL_NO_CMS
    ERR_load_CMS_strings();
# endif
# ifndef OPENSSL_NO_JPAKE
    ERR_load_JPAKE_strings();
# endif
# ifndef OPENSSL_NO_HSS
    ERR_load_HSS_strings();
# endif
# ifndef OPENSSL_NO_XMSS
    ERR_load_XMSS_strings();
# endif
# ifndef OPENSSL_NO_XMSSMT
    ERR_load_XMSSMT_strings();
# endif
# ifndef OPENSSL_NO_DILITHIUM
    ERR_load_DILITHIUM_strings();
# endif
# ifndef OPENSSL_NO_SPHINCS
    ERR_load_SPHINCS_strings();
# endif
# ifndef OPENSSL_NO_FRODODH
    ERR_load_FRODODH_strings();
# endif
# ifndef OPENSSL_NO_SAMWISE
    ERR_load_SAMWISE_strings();
# endif
# ifndef OPENSSL_NO_RAINBOW
    ERR_load_RAINBOW_strings();
# endif
# if !defined(OPENSSL_NO_NHDH)
    ERR_load_NHDH_strings();
# endif
# ifndef OPENSSL_NO_SIDH
    ERR_load_SIDH_strings();
# endif
# ifndef OPENSSL_NO_CMC
    ERR_load_CMC_strings();
# endif
# ifndef OPENSSL_NO_NTRUP
    ERR_load_NTRUP_strings();
# endif
# ifndef OPENSSL_NO_KYBER
    ERR_load_KYBER_strings();
# endif
# ifndef OPENSSL_NO_SIKE
    ERR_load_SIKE_strings();
# endif
# ifndef OPENSSL_NO_FRODOKEM
    ERR_load_FRODOKEM_strings();
# endif
#endif
}
