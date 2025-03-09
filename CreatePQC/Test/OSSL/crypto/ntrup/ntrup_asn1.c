/* ntrup_asn1.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/ntrup.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>

/* Override the default free and new methods */
static int ntrup_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)NTRUP_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        NTRUP_free((NTRUP *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(NTRUPPrivateKey, ntrup_cb) = {
        ASN1_SIMPLE(NTRUP, version, LONG),
        ASN1_SIMPLE(NTRUP, priv_key, ASN1_OCTET_STRING),
        ASN1_SIMPLE(NTRUP, pub_key, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_cb(NTRUP, NTRUPPrivateKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(NTRUP, NTRUPPrivateKey, NTRUPPrivateKey)

NTRUP *d2i_NTRUPPublicKey(NTRUP **a, const unsigned char **pp, long length) {
    NTRUP *ntrup = NULL;
    ASN1_OCTET_STRING *pub_key = NULL;

    ntrup = NTRUP_new();
    if (ntrup == NULL)
        return NULL;

    pub_key = d2i_ASN1_OCTET_STRING(NULL, pp, length);
    if (pub_key == NULL) {
        NTRUP_free(ntrup);
        return NULL;
    }

    if (a) {
        if (*a)
            NTRUP_free(*a);
        *a = ntrup;
    }

    ntrup->pub_key = pub_key;
    return ntrup;
}

int i2d_NTRUPPublicKey(const NTRUP *a, unsigned char **pp) {
    return i2d_ASN1_OCTET_STRING(a->pub_key, pp);
}

ASN1_SEQUENCE_cb(NTRUPKemInfo, ntrup_cb) = {
        ASN1_SIMPLE(NTRUP, kem_info, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END_cb(NTRUP, NTRUPKemInfo)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(NTRUP, NTRUPKemInfo, NTRUPKemInfo)

