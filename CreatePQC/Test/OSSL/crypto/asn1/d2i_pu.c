/* crypto/asn1/d2i_pu.c */
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
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_CMC
# include <openssl/cmc.h>
#endif
#ifndef OPENSSL_NO_DILITHIUM
# include <openssl/dilithium.h>
#endif
#ifndef OPENSSL_NO_FRODODH
# include <openssl/frododh.h>
#endif
#ifndef OPENSSL_NO_FRODOKEM
# include <openssl/frodokem.h>
#endif
#ifndef OPENSSL_NO_HSS
# include <openssl/hss.h>
#endif
#ifndef OPENSSL_NO_KYBER
# include <openssl/kyber.h>
#endif
#ifndef OPENSSL_NO_NHDH
# include <openssl/nhdh.h>
#endif
#ifndef OPENSSL_NO_NTRUP
# include <openssl/ntrup.h>
#endif
#ifndef OPENSSL_NO_RAINBOW
# include <openssl/rainbow.h>
#endif
#ifndef OPENSSL_NO_SAMWISE
# include <openssl/samwise.h>
#endif
#ifndef OPENSSL_NO_SIDH
# include <openssl/sidh.h>
#endif
#ifndef OPENSSL_NO_SIKE
# include <openssl/sike.h>
#endif
#ifndef OPENSSL_NO_SPHINCS
# include <openssl/sphincs.h>
#endif
#ifndef OPENSSL_NO_XMSS
# include <openssl/xmss.h>
#endif
#ifndef OPENSSL_NO_XMSSMT
# include <openssl/xmssmt.h>
#endif

/* Note that this function does NOT transfer ownership of the buffer to the
 * returned EVP_PKEY. The user must still free the memory pointed to by p.
 * Note that this will only work for quantum-safe key exchanges.
 */
EVP_PKEY *o2i_PublicKey(int type, EVP_PKEY **a, const unsigned char *p,
                        long length)
{
    EVP_PKEY *ret;

    if (p == NULL) {
        ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
        return (NULL);
    }

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            return (NULL);
        }
    } else
        ret = *a;

    if (!EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
        goto err;
    }

    switch (EVP_PKEY_id(ret)) {
#ifndef OPENSSL_NO_FRODODH
    case EVP_PKEY_FRODODH:
        if ((ret->pkey.frododh = FRODODH_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.frododh->my_public_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.frododh->my_public_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        ret->pkey.frododh->nid = type;
        break;
#endif
#ifndef OPENSSL_NO_NHDH
    case EVP_PKEY_NHDH:
        if ((ret->pkey.nhdh = NHDH_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.nhdh->my_public_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.nhdh->my_public_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        ret->pkey.nhdh->nid = type;
        break;
#endif
#ifndef OPENSSL_NO_SAMWISE
    case EVP_PKEY_SAMWISE:
        if ((ret->pkey.samwise = SAMWISE_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.samwise->my_public_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.samwise->my_public_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        ret->pkey.samwise->nid = type;
        break;
#endif
#ifndef OPENSSL_NO_SIDH
    case EVP_PKEY_SIDH:
        if ((ret->pkey.sidh = SIDH_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.sidh->my_public_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.sidh->my_public_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        if ((ret->pkey.sike = SIKE_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.sike->pub_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.sike->pub_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        if ((ret->pkey.kyber = KYBER_new()) == NULL) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_EVP_LIB);
            goto err;
        }
        ret->pkey.kyber->pub_key = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.kyber->pub_key, p, length)) {
            ASN1err(ASN1_F_O2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
    default:
        ASN1err(ASN1_F_O2I_PUBLICKEY, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
    }

    if (a != NULL)
        (*a) = ret;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        EVP_PKEY_free(ret);
    return NULL;
}

EVP_PKEY *o2i_KemInfo(int type, EVP_PKEY **a, const unsigned char *p,
                        long length)
{
    EVP_PKEY *ret;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_EVP_LIB);
            return (NULL);
        }
    } else
        ret = *a;

    if (!EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_EVP_LIB);
        goto err;
    }

    switch (EVP_PKEY_id(ret)) {
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        if ((ret->pkey.sike = SIKE_new()) == NULL) {
            ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_EVP_LIB);
            goto err;
        }

        ret->pkey.sike->kem_info = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.sike->kem_info, p, length)) {
            ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        if ((ret->pkey.kyber = KYBER_new()) == NULL) {
            ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_EVP_LIB);
            goto err;
        }

        ret->pkey.kyber->kem_info = ASN1_OCTET_STRING_new();
        if (!ASN1_OCTET_STRING_set(ret->pkey.kyber->kem_info, p, length)) {
            ASN1err(ASN1_F_O2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
    default:
        ASN1err(ASN1_F_O2I_KEMINFO, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
    }

    if (a != NULL)
        (*a) = ret;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        EVP_PKEY_free(ret);
    return NULL;
}

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
                        long length)
{
    EVP_PKEY *ret;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
            return (NULL);
        }
    } else
        ret = *a;

    if (!EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
        goto err;
    }

    switch (EVP_PKEY_id(ret)) {
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
        /* TMP UGLY CAST */
        if ((ret->pkey.rsa = d2i_RSAPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        /* TMP UGLY CAST */
        if (!d2i_DSAPublicKey(&(ret->pkey.dsa),
                              (const unsigned char **)pp, length)) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        if (!o2i_ECPublicKey(&(ret->pkey.ec),
                             (const unsigned char **)pp, length)) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_CMC
    case EVP_PKEY_CMC:
        if ((ret->pkey.cmc = d2i_CMCPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_DILITHIUM
    case EVP_PKEY_DILITHIUM:
        if ((ret->pkey.dilithium = d2i_DILITHIUMPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_FRODODH
    case EVP_PKEY_FRODODH:
        if ((ret->pkey.frododh = d2i_FRODODHPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_FRODOKEM
    case EVP_PKEY_FRODOKEM:
        if ((ret->pkey.frodokem = d2i_FRODOKEMPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_HSS
    case EVP_PKEY_HSS:
        if ((ret->pkey.hss = d2i_HSSPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        if ((ret->pkey.kyber = d2i_KYBERPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_NHDH
    case EVP_PKEY_NHDH:
        if ((ret->pkey.nhdh = d2i_NHDHPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_NTRUP
    case EVP_PKEY_NTRUP:
        if ((ret->pkey.ntrup = d2i_NTRUPPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_RAINBOW
    case EVP_PKEY_RAINBOW:
        if ((ret->pkey.rainbow = d2i_RAINBOWPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SAMWISE
    case EVP_PKEY_SAMWISE:
        if ((ret->pkey.samwise = d2i_SAMWISEPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SIDH
    case EVP_PKEY_SIDH:
        if ((ret->pkey.sidh = d2i_SIDHPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        if ((ret->pkey.sike = d2i_SIKEPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SPHINCS
    case EVP_PKEY_SPHINCS:
        if ((ret->pkey.sphincs = d2i_SPHINCSPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_XMSS
    case EVP_PKEY_XMSS:
        if ((ret->pkey.xmss = d2i_XMSSPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_XMSSMT
    case EVP_PKEY_XMSSMT:
        if ((ret->pkey.xmssmt = d2i_XMSSMTPublicKey(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
    default:
        ASN1err(ASN1_F_D2I_PUBLICKEY, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
        /* break; */
    }
    if (a != NULL)
        (*a) = ret;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        EVP_PKEY_free(ret);
    return (NULL);
}

EVP_PKEY *d2i_KemInfo(int type, EVP_PKEY **a, const unsigned char **pp, long length) {
    EVP_PKEY *ret;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_EVP_LIB);
            return (NULL);
        }
    } else
        ret = *a;

    if (!EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_EVP_LIB);
        goto err;
    }

    switch (EVP_PKEY_id(ret)) {
#ifndef OPENSSL_NO_CMC
    case EVP_PKEY_CMC:
        if ((ret->pkey.cmc = d2i_CMCKemInfo(NULL,
                                            (const unsigned char **)pp,
                                            length)) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_FRODOKEM
    case EVP_PKEY_FRODOKEM:
        if ((ret->pkey.frodokem = d2i_FRODOKEMKemInfo(NULL,
                                                      (const unsigned char **)pp,
                                                      length)) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_KYBER
    case EVP_PKEY_KYBER:
        if ((ret->pkey.kyber = d2i_KYBERKemInfo(NULL,
                                                (const unsigned char **)pp,
                                                length)) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_NTRUP
    case EVP_PKEY_NTRUP:
        if ((ret->pkey.ntrup = d2i_NTRUPKemInfo(NULL,
                                               (const unsigned char **)pp,
                                               length)) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENSSL_NO_SIKE
    case EVP_PKEY_SIKE:
        if ((ret->pkey.sike = d2i_SIKEKemInfo(NULL,
                                              (const unsigned char **)pp,
                                              length)) == NULL) {
            ASN1err(ASN1_F_D2I_KEMINFO, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
    default:
        ASN1err(ASN1_F_D2I_KEMINFO, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        goto err;
        /* break; */
    }
    if (a != NULL)
        (*a) = ret;
    return (ret);
 err:
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        EVP_PKEY_free(ret);
    return (NULL);
}
