/** @file cmsQSVerify.c QS Verify a QS signed CMS message.
 *
 * @copyright Copyright (C) 2018-2019, ISARA Corporation, All Rights Reserved.
 */

/* Modified.  Was genpkey.c. 
 */

/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>

#include "../apps/apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>

#define X509_NAME_LINE_LENGTH 128

#undef PROG
#define PROG    cmsQSVerify_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    char *passin = NULL;
    char *passargin = NULL;
    char *passin_qs = NULL;
    char *passargin_qs = NULL;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *classical_privkey = NULL;

    BIO *bio_cmsin = NULL;
    BIO *bio_cmsout = NULL;
    const char *file_cmsin = NULL;

    CMS_ContentInfo *cms = NULL;
    CMS_ContentInfo *cms_qs_signed = NULL;
    BIO *cmscont = NULL;

    int si_index = 0;
    CMS_SignerInfo *cms_si = NULL;
    STACK_OF(CMS_SignerInfo) *cms_si_stack = NULL;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    X509_ATTRIBUTE *altsigalg_attrib = NULL;
    X509_ATTRIBUTE *altsigval_attrib = NULL;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    X509_NAME *issuer = NULL;
    char name[X509_NAME_LINE_LENGTH];
    ASN1_INTEGER *serial = NULL;
    char *s = NULL;


    ERR_load_crypto_strings();
    ENGINE_load_dynamic();

    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
        } else if (strcmp(*args, "-cmsin") == 0) {
            if (!args[1])
                goto bad;
            file_cmsin = *(++args);
        } else {
            badarg = 1;
        }
        args++;
    }

    if (file_cmsin == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl cmsQSVerify [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-cmsin file        The CMS message with an MPKA certificate in it.\n");
        goto end;
    }

    bio_cmsin = BIO_new_file(file_cmsin, "rb");
    cms = SMIME_read_CMS(bio_cmsin, &cmscont);
    if (cms == NULL) {
        BIO_printf(bio_err, "Bad CMS message.\n");
        goto end;
    }

    /* This does a lot of the ASN.1 decoding that is required in order for
     *  CMS_get0_SignerInfos() to work properly.
     */
    if (CMS_verify(cms, NULL, NULL, cmscont, NULL, CMS_NO_SIGNER_CERT_VERIFY) == 0) {
        BIO_printf(bio_err, "CMS_verify failed.\n");
        goto end;
    }

    /* Do not need bio_cmsin any more. */
    BIO_free_all(bio_cmsin);
    bio_cmsin = NULL;

    cms_si_stack = CMS_get0_SignerInfos(cms);
    if (cms_si_stack == NULL) {
        BIO_printf(bio_err, "No signer certificates.\n");
        goto end;
    }

    /* We have to try all the SignerInfos because we don't have a private key
     * to match against.
     */
    for (si_index = 0; si_index < sk_CMS_SignerInfo_num(cms_si_stack); si_index++) {
        cms_si = sk_CMS_SignerInfo_value(cms_si_stack, si_index);

        if (cms_si == NULL) {
            BIO_printf(bio_err, "Expecting CMS_SignerInfo but none there.\n");
            goto end;
        }

        if (CMS_SignerInfo_get0_signer_id(cms_si, NULL, &issuer, &serial) == 0) {
            BIO_printf(bio_err, "Could not get signer info identifier.\n");
            goto end;
        }

        s = i2s_ASN1_INTEGER(NULL, serial);
        if (s == NULL) {
            BIO_printf(bio_err, "Could not decode serial number.\n");
            goto end;
        }

        if (CMS_SignerInfo_altverify(cms_si, cmscont) <= 0) {
            BIO_printf(bio_err, "NOT QS Verified: ");
        } else {
            BIO_printf(bio_err, "Successfully QS Verified: ");
            ret = 0;
        }
        BIO_printf(bio_err, "serial number:[%s] ", s);
        BIO_printf(bio_err, "issuer:[%s]\n", X509_NAME_oneline(issuer, name, X509_NAME_LINE_LENGTH));

        if (s) {
            OPENSSL_free(s);
        }
        s = NULL;
    }

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    EVP_MD_CTX_cleanup(&mctx);
    if (tmpctx)
        EVP_PKEY_CTX_free(tmpctx);
    if (bio_cmsin)
        BIO_free_all(bio_cmsin);
    if (bio_cmsout)
        BIO_free_all(bio_cmsout);
    if (cmscont)
        BIO_free_all(cmscont);
    if (cms)
        CMS_ContentInfo_free(cms);
    if (cms_qs_signed)
        CMS_ContentInfo_free(cms_qs_signed);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (altsigalg_attrib)
        X509_ATTRIBUTE_free(altsigalg_attrib);
    if (altsigval_attrib)
        X509_ATTRIBUTE_free(altsigval_attrib);

    if (passargin && passin)
        OPENSSL_free(passin);
    if (passargin_qs && passin_qs)
        OPENSSL_free(passin_qs);
    if (s)
        OPENSSL_free(s);

    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
