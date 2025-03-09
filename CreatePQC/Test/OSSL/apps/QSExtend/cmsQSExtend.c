/** @file cmsQSExtend.c Load QS private key and traditional signed cms
 * message with MPKA certificate and sign it.
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

#undef PROG
#define PROG    cmsQSExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    char *passin_qs = NULL;
    char *passargin_qs = NULL;
    int qs_key_format = FORMAT_PEM;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *classical_privkey = NULL;

    BIO *bio_cmsin = NULL;
    BIO *bio_cmsout = NULL;
    const char *file_qs_priv = NULL;
    const char *file_cmsin = NULL;
    const char *file_cmsout = NULL;

    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    CMS_ContentInfo *cms_qs_signed = NULL;
    BIO *cmscont = NULL;

    STACK_OF(X509) *cert_stack = NULL;
    int cert_index = 0;
    CMS_SignerInfo *cms_si = NULL;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    X509_ATTRIBUTE *altsigalg_attrib = NULL;
    X509_ATTRIBUTE *altsigval_attrib = NULL;
    int noattr_flag = 0;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

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
        } else if (strcmp(*args, "-cmsout") == 0) {
            if (!args[1])
                goto bad;
            file_cmsout = *(++args);
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-privqs_engine") == 0) {
            qs_key_format = FORMAT_ENGINE;
        } else if (strcmp(*args, "-passinqs") == 0) {
            if (--argc < 1)
                goto bad;
            passargin_qs = *(++args);
        } else if (strcmp(*args, "-noattr") == 0) {
            noattr_flag = CMS_NOATTR;
        } else {
            badarg = 1;
        }
        args++;
    }

    if (file_cmsin == NULL)
        badarg = 1;

    if (file_cmsout == NULL)
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl cmsQSExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-cmsin file        The original CMS message with an MPKA certificate in it.\n");
        BIO_printf(bio_err,
                   "-cmsout file       The newly signed CMS message.\n");
        BIO_printf(bio_err,
                   "-privqs file       The extended private QS key with the classical key.\n");
        BIO_printf(bio_err,
                   "-privqs_engine     The private QS key should be loaded via the engine. Optional.\n");
        BIO_printf(bio_err,
                   "-passinqs          The private QS key password source. Optional.\n");
        BIO_printf(bio_err,
                   "-noattr            Do not include any signed attributes. Optional.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin_qs, NULL, &passin_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password for the QS private key.\n");
        goto end;
    }


    /* Read in the classical private key that will be used to re-sign
     * this cert. If an engine is being used to read in the private key there
     * will be extra stuff for the state.  Remove it.
     */
    if (qs_key_format == FORMAT_ENGINE) {
        char *tmp1 = strstr(file_qs_priv, "::");
        if (tmp1 == NULL) {
            BIO_puts(bio_err, "Engine private key, but no state separator (::).\n");
            goto end;
        }

        char *tmp2 = OPENSSL_malloc((int)(tmp1 - file_qs_priv + 1));
        if (tmp2 == NULL) {
            BIO_puts(bio_err, "Memory allocation failure.\n");
            goto end;
        }

        memcpy(tmp2, file_qs_priv, tmp1 - file_qs_priv);
        tmp2[tmp1 - file_qs_priv] = '\0';
        classical_privkey = load_key(bio_err, tmp2, FORMAT_PEM, 0, passin_qs, e, "Classical Private Key");
        OPENSSL_free(tmp2);
    } else {
        classical_privkey = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, passin_qs, e, "Classical Private Key");
    }

    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate error message. */
        goto end;
    }

    pkey_qs_priv = load_alt_key(bio_err, file_qs_priv, qs_key_format, 0, passin_qs, e, "QS Private Key");
    if (pkey_qs_priv == NULL) {
        /* load_key() has already printed an appropriate error message. */
        goto end;
    }

    /* Ensure the private key is actually a QS key */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv))) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum-safe signature algorithm.\n");
        goto end;
    }

    bio_cmsin = BIO_new_file(file_cmsin, "rb");
    cms = SMIME_read_CMS(bio_cmsin, &cmscont);
    if (cms == NULL) {
        BIO_printf(bio_err, "Bad CMS message.\n");
        goto end;
    }

    if (CMS_verify(cms, NULL, NULL, cmscont, NULL, CMS_NO_SIGNER_CERT_VERIFY) == 0) {
        BIO_printf(bio_err, "CMS_verify failed.\n");
        goto end;
    }

    /* don't need bio_cmsin any more. */
    BIO_free_all(bio_cmsin);
    bio_cmsin = NULL;

    cert_stack = CMS_get0_signers(cms);
    if (cert_stack == NULL) {
        BIO_printf(bio_err, "No signer certificates.\n");
    }

    for (cert_index = 0; cert_index < sk_X509_num(cert_stack); cert_index++) {
       cert = sk_X509_value(cert_stack, cert_index);
       if (X509_check_alt_private_key(cert, pkey_qs_priv) == 1) {
           break;
       }
    }

    if (cert_index == sk_X509_num(cert_stack)) {
        BIO_printf(bio_err, "No matching Alt Public Keys.\n");
        goto end;
    }

    /* We now re-sign with QS private key and extend the SingnerInfo using
     * unsigned attributes.
     */

    bio_cmsin = BIO_new_file(file_cmsin, "rb");
    cms_qs_signed = CMS_sign(NULL, NULL, NULL, bio_cmsin, CMS_TEXT | CMS_PARTIAL | CMS_DETACHED);
    if (cms_qs_signed == NULL) {
        BIO_printf(bio_err, "Could not re-open the input file.\n");
        goto end;
    }

    cms_si = CMS_add1_signer(cms_qs_signed, cert, classical_privkey, EVP_sha256(), noattr_flag);
    if (cms_si == NULL) {
        BIO_printf(bio_err, "Could not add the signer.\n");
        goto end;
    }

    if (CMS_SignerInfo_set1_altpriv(cms_si, pkey_qs_priv) == 0) {
        BIO_printf(bio_err, "Could not set alt private key in signer info.\n");
        goto end;
    }

    /* Write the new signed CMS message. */
    bio_cmsout = BIO_new_file(file_cmsout, "wb");
    if (SMIME_write_CMS(bio_cmsout, cms_qs_signed, cmscont, CMS_PARTIAL | CMS_DETACHED) == 0) {
        BIO_puts(bio_err, "Error writing new certificate.\n");
        goto end;
    }

    ret = 0;

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

    if (passargin_qs && passin_qs)
        OPENSSL_free(passin_qs);
    if (cert_stack)
        sk_X509_free(cert_stack);
    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
