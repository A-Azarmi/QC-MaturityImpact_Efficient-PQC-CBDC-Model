/* crypto/cms/cms_sd.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include "cms_lcl.h"
#include "asn1_locl.h"

/* CMS SignedData Utilities */

DECLARE_ASN1_ITEM(CMS_SignedData)

static X509_ATTRIBUTE *create_ALTSIG_ATTRIBUTE(ASN1_OCTET_STRING *altsig) {
    X509_ATTRIBUTE *attr = NULL;

    attr = X509_ATTRIBUTE_create(NID_cmsAltSignatureValue, V_ASN1_OCTET_STRING, altsig);
    if (attr == NULL) {
        fprintf(stderr, "Failed to create the ALTSIG attribute.\n");
        goto end;
    }

end:
    return attr;
}

static X509_ATTRIBUTE *create_ALTSIGALG_ATTRIBUTE(X509_ALGOR *altsigalg) {
    X509_ATTRIBUTE *attr = NULL;
    unsigned char *p = NULL;
    unsigned char *data = NULL;
    ASN1_STRING *astr = NULL;
    int i = 0;

    i = i2d_X509_ALGOR(altsigalg, NULL);
    if (i < 0) {
        fprintf(stderr, "Failed to get ASN.1 size of ALTSIGALG attribute.\n");
        goto end;
    }

    data = OPENSSL_malloc(i);
    if (data == NULL) {
        fprintf(stderr, "Memory failure during ALTSIGALG attribute creation.\n");
        goto end;
    }

    p=data;
    i = i2d_X509_ALGOR(altsigalg, &p);
    if (i < 0) {
        fprintf(stderr, "Failed to ASN.1 encode the ALTSIGALG attribute.\n");
        goto end;
    }

    astr = ASN1_STRING_new();
    if (!ASN1_STRING_set(astr, data, i)) {
        fprintf(stderr, "Failed to alloc/set string for ALTSIGALG attribute.\n");
        ASN1_STRING_free(astr);
        goto end;
    }

    attr = X509_ATTRIBUTE_create(NID_cmsAltSignatureAlgorithm, V_ASN1_SEQUENCE, astr);
    if (attr == NULL) {
        ASN1_STRING_free(astr);
        fprintf(stderr, "Failed to create the ALTSIGALG attribute.\n");
        goto end;
    }

end:
    OPENSSL_free(data);
    return attr;
}

static EVP_PKEY *get_pubkey_from_SAPKI(SUBJECT_ALT_PUBLIC_KEY_INFO *sapki) {
    X509_PUBKEY *x509_pub_qs = NULL;
    EVP_PKEY *qs_pub_key = NULL;

    /* Convert the x509 formatted public key into a pkey */
    x509_pub_qs = X509_PUBKEY_new();
    if (x509_pub_qs == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        goto end;
    }
    X509_ALGOR_free(x509_pub_qs->algor);
    ASN1_BIT_STRING_free(x509_pub_qs->public_key);

    x509_pub_qs->algor = sapki->algor;
    x509_pub_qs->public_key = sapki->public_key;
    x509_pub_qs->pkey = NULL;

    qs_pub_key = X509_PUBKEY_get(x509_pub_qs);

    x509_pub_qs->algor = NULL;
    x509_pub_qs->public_key = NULL;
    X509_PUBKEY_free(x509_pub_qs);
    x509_pub_qs = NULL;

    if (qs_pub_key == NULL) {
        fprintf(stderr, "Error converting ALT public key into a PKEY.\n");
        goto end;
    }

end:

    return qs_pub_key;
}

static EVP_PKEY *get_SAPKI_from_x509(X509 *cert) {
    int qs_pub_key_ind = -1;
    X509_EXTENSION *qs_pub_key_ext = NULL;
    EVP_PKEY *pk = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;

    /* Find the issuer's ALT public key extension. */
    qs_pub_key_ind = X509_get_ext_by_NID(cert, NID_subjectAltPublicKeyInfo, -1);
    if (qs_pub_key_ind < 0) {
        goto end;
    }

    qs_pub_key_ext = X509_get_ext(cert, qs_pub_key_ind);
    if (qs_pub_key_ext == NULL) {
        goto end;
    }

    sapki = X509V3_EXT_d2i(qs_pub_key_ext);
    if (sapki == NULL) {
        goto end;
    }

    pk = get_pubkey_from_SAPKI(sapki);
    if (pk == NULL) {
        goto end;
    }

end:
    if (sapki)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);

    return pk;
}

static ASN1_OCTET_STRING *get_ALTSIG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_cmsAltSignatureValue);
    ASN1_OCTET_STRING *altsig = NULL;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_OCTET_STRING)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    altsig = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_OCTET_STRING, NULL);
    if (altsig == NULL) {
        fprintf (stderr, "Couldn't get ASN1 data from attribute.\n") ;
        goto err;
    }

    return altsig;

err:
    return NULL;
}

static CMS_SignedData *cms_get0_signed(CMS_ContentInfo *cms)
{
    if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_signed) {
        CMSerr(CMS_F_CMS_GET0_SIGNED, CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA);
        return NULL;
    }
    return cms->d.signedData;
}

static CMS_SignedData *cms_signed_data_init(CMS_ContentInfo *cms)
{
    if (cms->d.other == NULL) {
        cms->d.signedData = M_ASN1_new_of(CMS_SignedData);
        if (!cms->d.signedData) {
            CMSerr(CMS_F_CMS_SIGNED_DATA_INIT, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        cms->d.signedData->version = 1;
        cms->d.signedData->encapContentInfo->eContentType =
            OBJ_nid2obj(NID_pkcs7_data);
        cms->d.signedData->encapContentInfo->partial = 1;
        ASN1_OBJECT_free(cms->contentType);
        cms->contentType = OBJ_nid2obj(NID_pkcs7_signed);
        return cms->d.signedData;
    }
    return cms_get0_signed(cms);
}

/* Just initialize SignedData e.g. for certs only structure */

int CMS_SignedData_init(CMS_ContentInfo *cms)
{
    if (cms_signed_data_init(cms))
        return 1;
    else
        return 0;
}

/* Check structures and fixup version numbers (if necessary) */

static void cms_sd_set_version(CMS_SignedData *sd)
{
    int i;
    CMS_CertificateChoices *cch;
    CMS_RevocationInfoChoice *rch;
    CMS_SignerInfo *si;

    for (i = 0; i < sk_CMS_CertificateChoices_num(sd->certificates); i++) {
        cch = sk_CMS_CertificateChoices_value(sd->certificates, i);
        if (cch->type == CMS_CERTCHOICE_OTHER) {
            if (sd->version < 5)
                sd->version = 5;
        } else if (cch->type == CMS_CERTCHOICE_V2ACERT) {
            if (sd->version < 4)
                sd->version = 4;
        } else if (cch->type == CMS_CERTCHOICE_V1ACERT) {
            if (sd->version < 3)
                sd->version = 3;
        }
    }

    for (i = 0; i < sk_CMS_RevocationInfoChoice_num(sd->crls); i++) {
        rch = sk_CMS_RevocationInfoChoice_value(sd->crls, i);
        if (rch->type == CMS_REVCHOICE_OTHER) {
            if (sd->version < 5)
                sd->version = 5;
        }
    }

    if ((OBJ_obj2nid(sd->encapContentInfo->eContentType) != NID_pkcs7_data)
        && (sd->version < 3))
        sd->version = 3;

    for (i = 0; i < sk_CMS_SignerInfo_num(sd->signerInfos); i++) {
        si = sk_CMS_SignerInfo_value(sd->signerInfos, i);
        if (si->sid->type == CMS_SIGNERINFO_KEYIDENTIFIER) {
            if (si->version < 3)
                si->version = 3;
            if (sd->version < 3)
                sd->version = 3;
        } else if (si->version < 1)
            si->version = 1;
    }

    if (sd->version < 1)
        sd->version = 1;

}

/* Copy an existing messageDigest value */

static int cms_copy_messageDigest(CMS_ContentInfo *cms, CMS_SignerInfo *si)
{
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *sitmp;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        ASN1_OCTET_STRING *messageDigest;
        sitmp = sk_CMS_SignerInfo_value(sinfos, i);
        if (sitmp == si)
            continue;
        if (CMS_signed_get_attr_count(sitmp) < 0)
            continue;
        if (OBJ_cmp(si->digestAlgorithm->algorithm,
                    sitmp->digestAlgorithm->algorithm))
            continue;
        messageDigest = CMS_signed_get0_data_by_OBJ(sitmp,
                                                    OBJ_nid2obj
                                                    (NID_pkcs9_messageDigest),
                                                    -3, V_ASN1_OCTET_STRING);
        if (!messageDigest) {
            CMSerr(CMS_F_CMS_COPY_MESSAGEDIGEST,
                   CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE);
            return 0;
        }

        if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest,
                                        V_ASN1_OCTET_STRING,
                                        messageDigest, -1))
            return 1;
        else
            return 0;
    }
    CMSerr(CMS_F_CMS_COPY_MESSAGEDIGEST, CMS_R_NO_MATCHING_DIGEST);
    return 0;
}

int cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid, X509 *cert, int type)
{
    switch (type) {
    case CMS_SIGNERINFO_ISSUER_SERIAL:
        if (!cms_set1_ias(&sid->d.issuerAndSerialNumber, cert))
            return 0;
        break;

    case CMS_SIGNERINFO_KEYIDENTIFIER:
        if (!cms_set1_keyid(&sid->d.subjectKeyIdentifier, cert))
            return 0;
        break;

    default:
        CMSerr(CMS_F_CMS_SET1_SIGNERIDENTIFIER, CMS_R_UNKNOWN_ID);
        return 0;
    }

    sid->type = type;

    return 1;
}

int cms_SignerIdentifier_get0_signer_id(CMS_SignerIdentifier *sid,
                                        ASN1_OCTET_STRING **keyid,
                                        X509_NAME **issuer,
                                        ASN1_INTEGER **sno)
{
    if (sid->type == CMS_SIGNERINFO_ISSUER_SERIAL) {
        if (issuer)
            *issuer = sid->d.issuerAndSerialNumber->issuer;
        if (sno)
            *sno = sid->d.issuerAndSerialNumber->serialNumber;
    } else if (sid->type == CMS_SIGNERINFO_KEYIDENTIFIER) {
        if (keyid)
            *keyid = sid->d.subjectKeyIdentifier;
    } else
        return 0;
    return 1;
}

int cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid, X509 *cert)
{
    if (sid->type == CMS_SIGNERINFO_ISSUER_SERIAL)
        return cms_ias_cert_cmp(sid->d.issuerAndSerialNumber, cert);
    else if (sid->type == CMS_SIGNERINFO_KEYIDENTIFIER)
        return cms_keyid_cert_cmp(sid->d.subjectKeyIdentifier, cert);
    else
        return -1;
}

static int cms_sd_asn1_ctrl(CMS_SignerInfo *si, int cmd)
{
    EVP_PKEY *pkey = si->pkey;
    int i;
    if (!pkey->ameth || !pkey->ameth->pkey_ctrl)
        return 1;
    i = pkey->ameth->pkey_ctrl(pkey, ASN1_PKEY_CTRL_CMS_SIGN, cmd, si);
    if (i == -2) {
        CMSerr(CMS_F_CMS_SD_ASN1_CTRL, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
        return 0;
    }
    if (i <= 0) {
        CMSerr(CMS_F_CMS_SD_ASN1_CTRL, CMS_R_CTRL_FAILURE);
        return 0;
    }
    return 1;
}

CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,
                                X509 *signer, EVP_PKEY *pk, const EVP_MD *md,
                                unsigned int flags)
{
    CMS_SignedData *sd;
    CMS_SignerInfo *si = NULL;
    X509_ALGOR *alg;
    int i, type;
    if (!X509_check_private_key(signer, pk)) {
        CMSerr(CMS_F_CMS_ADD1_SIGNER,
               CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return NULL;
    }
    sd = cms_signed_data_init(cms);
    if (!sd)
        goto err;
    si = M_ASN1_new_of(CMS_SignerInfo);
    if (!si)
        goto merr;
    X509_check_purpose(signer, -1, -1);

    CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
    CRYPTO_add(&signer->references, 1, CRYPTO_LOCK_X509);

    si->pkey = pk;
    si->signer = signer;
    EVP_MD_CTX_init(&si->mctx);
    si->pctx = NULL;

    if (flags & CMS_USE_KEYID) {
        si->version = 3;
        if (sd->version < 3)
            sd->version = 3;
        type = CMS_SIGNERINFO_KEYIDENTIFIER;
    } else {
        type = CMS_SIGNERINFO_ISSUER_SERIAL;
        si->version = 1;
    }

    if (!cms_set1_SignerIdentifier(si->sid, signer, type))
        goto err;

    if (md == NULL) {
        int def_nid;
        if (EVP_PKEY_get_default_digest_nid(pk, &def_nid) <= 0) {
            CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DEFAULT_DIGEST);
            goto err;
        }
        md = EVP_get_digestbynid(def_nid);
        if (md == NULL) {
            /* Now lets try the cms specific message digest */
            if (EVP_PKEY_get_cms_digest_nid(pk, &def_nid) <= 0) {
                CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DEFAULT_DIGEST);
                goto err;
            }
            md = EVP_get_digestbynid(def_nid);
            if (md == NULL) {
                CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DEFAULT_DIGEST);
                goto err;
            }
        }
    }

    if (!md) {
        CMSerr(CMS_F_CMS_ADD1_SIGNER, CMS_R_NO_DIGEST_SET);
        goto err;
    }

    cms_DigestAlgorithm_set(si->digestAlgorithm, md);

    /* See if digest is present in digestAlgorithms */
    for (i = 0; i < sk_X509_ALGOR_num(sd->digestAlgorithms); i++) {
        ASN1_OBJECT *aoid;
        alg = sk_X509_ALGOR_value(sd->digestAlgorithms, i);
        X509_ALGOR_get0(&aoid, NULL, NULL, alg);
        if (OBJ_obj2nid(aoid) == EVP_MD_type(md))
            break;
    }

    if (i == sk_X509_ALGOR_num(sd->digestAlgorithms)) {
        alg = X509_ALGOR_new();
        if (!alg)
            goto merr;
        cms_DigestAlgorithm_set(alg, md);
        if (!sk_X509_ALGOR_push(sd->digestAlgorithms, alg)) {
            X509_ALGOR_free(alg);
            goto merr;
        }
    }

    if (!(flags & CMS_KEY_PARAM) && !cms_sd_asn1_ctrl(si, 0))
        goto err;
    if (!(flags & CMS_NOATTR)) {
        /*
         * Initialialize signed attributes strutucture so other attributes
         * such as signing time etc are added later even if we add none here.
         */
        if (!si->signedAttrs) {
            si->signedAttrs = sk_X509_ATTRIBUTE_new_null();
            if (!si->signedAttrs)
                goto merr;
        }

        if (!(flags & CMS_NOSMIMECAP)) {
            STACK_OF(X509_ALGOR) *smcap = NULL;
            i = CMS_add_standard_smimecap(&smcap);
            if (i)
                i = CMS_add_smimecap(si, smcap);
            sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
            if (!i)
                goto merr;
        }
        if (flags & CMS_REUSE_DIGEST) {
            if (!cms_copy_messageDigest(cms, si))
                goto err;
            if (!(flags & (CMS_PARTIAL | CMS_KEY_PARAM)) &&
                !CMS_SignerInfo_sign(si))
                goto err;
        }
    }

    if (!(flags & CMS_NOCERTS)) {
        /* NB ignore -1 return for duplicate cert */
        if (!CMS_add1_cert(cms, signer))
            goto merr;
    }

    if (flags & CMS_KEY_PARAM) {
        if (flags & CMS_NOATTR) {
            si->pctx = EVP_PKEY_CTX_new(si->pkey, NULL);
            if (!si->pctx)
                goto err;
            if (EVP_PKEY_sign_init(si->pctx) <= 0)
                goto err;
            if (EVP_PKEY_CTX_set_signature_md(si->pctx, md) <= 0)
                goto err;
        } else if (EVP_DigestSignInit(&si->mctx, &si->pctx, md, NULL, pk) <=
                   0)
            goto err;
    }

    if (!sd->signerInfos)
        sd->signerInfos = sk_CMS_SignerInfo_new_null();
    if (!sd->signerInfos || !sk_CMS_SignerInfo_push(sd->signerInfos, si))
        goto merr;

    return si;

 merr:
    CMSerr(CMS_F_CMS_ADD1_SIGNER, ERR_R_MALLOC_FAILURE);
 err:
    if (si)
        M_ASN1_free_of(si, CMS_SignerInfo);
    return NULL;

}

int CMS_SignerInfo_set1_altpriv(CMS_SignerInfo *si, EVP_PKEY *altpriv) {
    if (si == NULL)
        return 0;
    if (altpriv == NULL)
        return 0;
    si->altpriv = altpriv;
    return 1;
}

static int cms_add1_signingTime(CMS_SignerInfo *si, ASN1_TIME *t)
{
    ASN1_TIME *tt;
    int r = 0;
    if (t)
        tt = t;
    else
        tt = X509_gmtime_adj(NULL, 0);

    if (!tt)
        goto merr;

    if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_signingTime,
                                    tt->type, tt, -1) <= 0)
        goto merr;

    r = 1;

 merr:

    if (!t)
        ASN1_TIME_free(tt);

    if (!r)
        CMSerr(CMS_F_CMS_ADD1_SIGNINGTIME, ERR_R_MALLOC_FAILURE);

    return r;

}

EVP_PKEY_CTX *CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si)
{
    return si->pctx;
}

EVP_MD_CTX *CMS_SignerInfo_get0_md_ctx(CMS_SignerInfo *si)
{
    return &si->mctx;
}

STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms)
{
    CMS_SignedData *sd;
    sd = cms_get0_signed(cms);
    if (!sd)
        return NULL;
    return sd->signerInfos;
}

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms)
{
    STACK_OF(X509) *signers = NULL;
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *si;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        if (si->signer) {
            if (!signers) {
                signers = sk_X509_new_null();
                if (!signers)
                    return NULL;
            }
            if (!sk_X509_push(signers, si->signer)) {
                sk_X509_free(signers);
                return NULL;
            }
        }
    }
    return signers;
}

void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer)
{
    if (signer) {
        CRYPTO_add(&signer->references, 1, CRYPTO_LOCK_X509);
        if (si->pkey)
            EVP_PKEY_free(si->pkey);
        si->pkey = X509_get_pubkey(signer);
    }
    if (si->signer)
        X509_free(si->signer);
    si->signer = signer;
}

int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si,
                                  ASN1_OCTET_STRING **keyid,
                                  X509_NAME **issuer, ASN1_INTEGER **sno)
{
    return cms_SignerIdentifier_get0_signer_id(si->sid, keyid, issuer, sno);
}

int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert)
{
    return cms_SignerIdentifier_cert_cmp(si->sid, cert);
}

int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *scerts,
                           unsigned int flags)
{
    CMS_SignedData *sd;
    CMS_SignerInfo *si;
    CMS_CertificateChoices *cch;
    STACK_OF(CMS_CertificateChoices) *certs;
    X509 *x;
    int i, j;
    int ret = 0;
    sd = cms_get0_signed(cms);
    if (!sd)
        return -1;
    certs = sd->certificates;
    for (i = 0; i < sk_CMS_SignerInfo_num(sd->signerInfos); i++) {
        si = sk_CMS_SignerInfo_value(sd->signerInfos, i);
        if (si->signer)
            continue;

        for (j = 0; j < sk_X509_num(scerts); j++) {
            x = sk_X509_value(scerts, j);
            if (CMS_SignerInfo_cert_cmp(si, x) == 0) {
                CMS_SignerInfo_set1_signer_cert(si, x);
                ret++;
                break;
            }
        }

        if (si->signer || (flags & CMS_NOINTERN))
            continue;

        for (j = 0; j < sk_CMS_CertificateChoices_num(certs); j++) {
            cch = sk_CMS_CertificateChoices_value(certs, j);
            if (cch->type != 0)
                continue;
            x = cch->d.certificate;
            if (CMS_SignerInfo_cert_cmp(si, x) == 0) {
                CMS_SignerInfo_set1_signer_cert(si, x);
                ret++;
                break;
            }
        }
    }
    return ret;
}

void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
                              X509 **signer, X509_ALGOR **pdig,
                              X509_ALGOR **psig)
{
    if (pk)
        *pk = si->pkey;
    if (signer)
        *signer = si->signer;
    if (pdig)
        *pdig = si->digestAlgorithm;
    if (psig)
        *psig = si->signatureAlgorithm;
}

ASN1_OCTET_STRING *CMS_SignerInfo_get0_signature(CMS_SignerInfo *si)
{
    return si->signature;
}

static int cms_SignerInfo_rawsign(EVP_PKEY *pkey, unsigned char *abuf, int alen, unsigned char **sig, size_t *siglen) {
    int ret = 0;
    *sig = NULL;
    *siglen = 0;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        goto end;
    }

    if (EVP_PKEY_sign_init(pctx) <= 0) {
        goto end;
    }

    if (EVP_PKEY_sign(pctx, NULL, siglen, abuf, alen) <= 0) {
        goto end;
    }

    *sig = OPENSSL_malloc(*siglen);
    if (*sig == NULL) {
        goto end;
    }

    if (EVP_PKEY_sign(pctx, *sig, siglen, abuf, alen) <= 0) {
        goto end;
    }

    ret = 1;

end:
    EVP_PKEY_CTX_free(pctx);

    if ((ret == 0 ) && (*sig != NULL)) {
        OPENSSL_free(*sig);
        *sig = NULL;
    }

    return ret;
}

static int cms_SignerInfo_content_sign(CMS_ContentInfo *cms,
                                       CMS_SignerInfo *si, BIO *chain)
{
    EVP_MD_CTX mctx;
    int r = 0;
    EVP_PKEY_CTX *pctx = NULL;
    int default_digest_nid = 0;
    unsigned char *cont = NULL;
    long contlen = 0;

    EVP_MD_CTX_init(&mctx);

    if (!si->pkey) {
        CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, CMS_R_NO_PRIVATE_KEY);
        return 0;
    }

    chain = BIO_find_type(chain, BIO_TYPE_STORE);
    if (chain == NULL)
        goto err;

    contlen = BIO_get_store_data(chain, &cont);
    if (contlen <= 0)
        goto err;

    if ((CMS_signed_get_attr_count(si) < 0)
        && (EVP_PKEY_get_default_digest_nid(si->pkey, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        /* There are no signed attributes and the pkey wants to do raw signing,
         * so do it against the content. The chain should have a store BIO.
         * Find it and sign the content of that BIO.
         */
        unsigned char *sig = NULL;
        size_t siglen = 0;

        if (cms_SignerInfo_rawsign(si->pkey, cont, (size_t)contlen, &sig, &siglen) <= 0)
            goto err;

        ASN1_STRING_set0(si->signature, sig, siglen);

        if (si->altpriv != NULL)
            if (!CMS_SignerInfo_altsign(si, cont, contlen))
                goto err;
    } else {
        if (!cms_DigestAlgorithm_find_ctx(&mctx, chain, si->digestAlgorithm))
            goto err;
        /* Set SignerInfo algortihm details if we used custom parametsr */
        if (si->pctx && !cms_sd_asn1_ctrl(si, 0))
            goto err;

        /*
         * If any signed attributes calculate and add messageDigest attribute
         */

        if (CMS_signed_get_attr_count(si) >= 0) {
            ASN1_OBJECT *ctype =
                cms->d.signedData->encapContentInfo->eContentType;
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int mdlen;
            if (!EVP_DigestFinal_ex(&mctx, md, &mdlen))
                goto err;
            if (!CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest,
                                             V_ASN1_OCTET_STRING, md, mdlen))
                goto err;
            /* Copy content type across */
            if (CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType,
                                            V_ASN1_OBJECT, ctype, -1) <= 0)
                goto err;
            if (!CMS_SignerInfo_sign(si))
                goto err;
            if (si->altpriv != NULL)
                if (!CMS_SignerInfo_altsign(si, NULL, 0))
                    goto err;
        } else if (si->pctx) {
            unsigned char *sig;
            size_t siglen;
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int mdlen;
            pctx = si->pctx;
            if (!EVP_DigestFinal_ex(&mctx, md, &mdlen))
                goto err;
            siglen = EVP_PKEY_size(si->pkey);
            sig = OPENSSL_malloc(siglen);
            if (!sig) {
                CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (EVP_PKEY_sign(pctx, sig, &siglen, md, mdlen) <= 0)
                goto err;
            ASN1_STRING_set0(si->signature, sig, siglen);

            if (si->altpriv != NULL)
                if (!CMS_SignerInfo_altsign(si, cont, contlen))
                    goto err;
        } else {
            unsigned char *sig;
            unsigned int siglen;
            sig = OPENSSL_malloc(EVP_PKEY_size(si->pkey));
            if (!sig) {
                CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!EVP_SignFinal(&mctx, sig, &siglen, si->pkey)) {
                CMSerr(CMS_F_CMS_SIGNERINFO_CONTENT_SIGN, CMS_R_SIGNFINAL_ERROR);
                OPENSSL_free(sig);
                goto err;
            }
            ASN1_STRING_set0(si->signature, sig, siglen);

            if (si->altpriv != NULL)
                if (!CMS_SignerInfo_altsign(si, cont, contlen))
                    goto err;
        }
    }

    r = 1;

 err:
    EVP_MD_CTX_cleanup(&mctx);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    return r;

}

int cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain)
{
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_SignerInfo *si;
    int i;
    sinfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        if (!cms_SignerInfo_content_sign(cms, si, chain))
            return 0;
    }
    cms->d.signedData->encapContentInfo->partial = 0;
    return 1;
}

int CMS_SignerInfo_sign(CMS_SignerInfo *si)
{
    EVP_MD_CTX *mctx = &si->mctx;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *abuf = NULL;
    int alen;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const EVP_MD *md = NULL;
    int default_digest_nid = -1;

    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        return 0;

    if (CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) < 0) {
        if (!cms_add1_signingTime(si, NULL))
            goto err;
    }

    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                         ASN1_ITEM_rptr(CMS_Attributes_Sign));
    if (!abuf)
        goto err;

    /* If EVP_PKEY_get_default_digest_nid() returns NID_UNDEF, then this
     * algorithm  wants to do raw signing, otherwise hash and sign.
     *
     * We couldn't just set si->digestAlgorithm to NULL because we still need
     * that to indicate which hash algo to use to hash the content.
     */
    if ((EVP_PKEY_get_default_digest_nid(si->pkey, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        int ret = cms_SignerInfo_rawsign(si->pkey, abuf, alen, &sig, &siglen);
        ASN1_STRING_set0(si->signature, sig, siglen);
        OPENSSL_free(abuf);
        return ret;
    }

    if (si->pctx)
        pctx = si->pctx;
    else {
        EVP_MD_CTX_init(mctx);
        if (EVP_DigestSignInit(mctx, &pctx, md, NULL, si->pkey) <= 0)
            goto err;
    }

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_CMS_SIGN, 0, si) <= 0) {
        CMSerr(CMS_F_CMS_SIGNERINFO_SIGN, CMS_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_DigestSignUpdate(mctx, abuf, alen) <= 0)
        goto err;
    if (EVP_DigestSignFinal(mctx, NULL, &siglen) <= 0)
        goto err;
    OPENSSL_free(abuf);
    abuf = OPENSSL_malloc(siglen);
    if (!abuf)
        goto err;
    if (EVP_DigestSignFinal(mctx, abuf, &siglen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                          EVP_PKEY_CTRL_CMS_SIGN, 1, si) <= 0) {
        CMSerr(CMS_F_CMS_SIGNERINFO_SIGN, CMS_R_CTRL_ERROR);
        goto err;
    }

    EVP_MD_CTX_cleanup(mctx);

    ASN1_STRING_set0(si->signature, abuf, siglen);

    return 1;

 err:
    if (abuf)
        OPENSSL_free(abuf);
    EVP_MD_CTX_cleanup(mctx);
    return 0;

}

int CMS_SignerInfo_altsign(CMS_SignerInfo *si, unsigned char *cont, long contlen) {
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *abuf = NULL;
    int alen = 0;
    unsigned char *sigbuf = NULL;
    size_t siglen = 0;
    const EVP_MD *md = NULL;
    ASN1_OCTET_STRING *sigoct = NULL;
    X509_ATTRIBUTE *sigalg = NULL;
    X509_ATTRIBUTE *sigval = NULL;
    X509_ALGOR *algor = NULL;
    int signid = 0;
    int status = 0;
    int default_digest_nid = -1;

    EVP_MD_CTX_init(&mctx);

    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        goto err;

    if (cont == NULL) {

        /* If we're not signing content, then we're signing signed attributes.
         * Add the signing time attribute.
         */
        if (CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) < 0) {
            if (!cms_add1_signingTime(si, NULL))
                goto err;
        }

        alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                             ASN1_ITEM_rptr(CMS_Attributes_Sign));
        if (!abuf)
            goto err;
        cont = abuf;
        contlen = alen;
    }

    /* If EVP_PKEY_get_default_digest_nid() returns NID_UNDEF, then this
     * algorithm  wants to do raw signing, otherwise hash and sign.
     *
     * We couldn't just set si->digestAlgorithm to NULL because we still need
     * that to indicate which hash algo to use to hash the content.
     */
    if ((EVP_PKEY_get_default_digest_nid(si->altpriv, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        if (cms_SignerInfo_rawsign(si->altpriv, cont, contlen, &sigbuf, &siglen) <= 0) {
            goto err;
        }

        /* Since we're doing raw signing... */
        signid = EVP_PKEY_base_id(si->altpriv);
    } else {
        if (EVP_DigestSignInit(&mctx, &pctx, md, NULL, si->altpriv) <= 0)
            goto err;

        if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                              EVP_PKEY_CTRL_CMS_SIGN, 0, si) <= 0) {
            CMSerr(CMS_F_CMS_SIGNERINFO_ALTSIGN, CMS_R_CTRL_ERROR);
            goto err;
        }

        if (EVP_DigestSignUpdate(&mctx, cont, contlen) <= 0)
            goto err;

        if (EVP_DigestSignFinal(&mctx, NULL, &siglen) <= 0)
            goto err;

        sigbuf = OPENSSL_malloc(siglen);
        if (!sigbuf)
            goto err;

        if (EVP_DigestSignFinal(&mctx, sigbuf, &siglen) <= 0)
            goto err;

        if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_SIGN,
                              EVP_PKEY_CTRL_CMS_SIGN, 1, si) <= 0) {
            CMSerr(CMS_F_CMS_SIGNERINFO_ALTSIGN, CMS_R_CTRL_ERROR);
            goto err;
        }

        if (!OBJ_find_sigid_by_algs(&signid, EVP_MD_type(md), EVP_PKEY_base_id(si->altpriv))) {
            goto err;
        }
    }

    algor = X509_ALGOR_new();
    if (algor == NULL)
        goto err;

    if (X509_ALGOR_set0(algor, OBJ_nid2obj(signid), V_ASN1_UNDEF, 0) == 0)
        goto err;

    sigalg = create_ALTSIGALG_ATTRIBUTE(algor);
    if (sigalg == NULL)
        goto err;

    sigoct = ASN1_OCTET_STRING_new();
    if (sigoct == NULL)
        goto err;

    sigoct->length = siglen;
    sigoct->data = sigbuf;
    siglen = 0;
    sigbuf = NULL;

    sigval = create_ALTSIG_ATTRIBUTE(sigoct);
    if (sigval == NULL)
        goto err;
    sigoct = NULL;

    if (CMS_unsigned_add1_attr(si, sigalg) == 0)
        goto err;

    if (CMS_unsigned_add1_attr(si, sigval) == 0)
        goto err;

    status = 1;

err:
    EVP_MD_CTX_cleanup(&mctx);
    if (sigbuf)
        OPENSSL_free(sigbuf);
    if (abuf)
        OPENSSL_free(abuf);
    if (sigoct)
        ASN1_OCTET_STRING_free(sigoct);
    if (sigalg)
        X509_ATTRIBUTE_free(sigalg);
    if (sigval)
        X509_ATTRIBUTE_free(sigval);
    if (algor)
        X509_ALGOR_free(algor);
    return status;
}

static int cms_SignerInfo_rawverify(EVP_PKEY *pkey, unsigned char *abuf, int alen, unsigned char *sig, size_t siglen) {
    int ret = 0;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        goto end;
    }

    if (EVP_PKEY_verify_init(pctx) <= 0) {
        goto end;
    }

    if (EVP_PKEY_verify(pctx, sig, siglen, abuf, alen) <= 0) {
        goto end;
    }

    ret = 1;

end:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int CMS_SignerInfo_verify(CMS_SignerInfo *si)
{
    EVP_MD_CTX *mctx = &si->mctx;
    unsigned char *abuf = NULL;
    int alen, r = -1;
    const EVP_MD *md = NULL;
    int default_digest_nid = -1;

    if (!si->pkey) {
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY, CMS_R_NO_PUBLIC_KEY);
        return -1;
    }

    alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                         ASN1_ITEM_rptr(CMS_Attributes_Verify));
    if (!abuf)
        goto err;

    if ((EVP_PKEY_get_default_digest_nid(si->pkey, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        r = cms_SignerInfo_rawverify(si->pkey, abuf, alen, si->signature->data, si->signature->length);
        OPENSSL_free(abuf);
        return r;
    }

    md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
    if (md == NULL)
        goto err;
    EVP_MD_CTX_init(mctx);
    if (EVP_DigestVerifyInit(mctx, &si->pctx, md, NULL, si->pkey) <= 0)
        goto err;

    if (!cms_sd_asn1_ctrl(si, 1))
        goto err;

    r = EVP_DigestVerifyUpdate(mctx, abuf, alen);
    OPENSSL_free(abuf);
    if (r <= 0) {
        r = -1;
        goto err;
    }
    r = EVP_DigestVerifyFinal(mctx,
                              si->signature->data, si->signature->length);
    if (r <= 0)
        CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY, CMS_R_VERIFICATION_FAILURE);
 err:
    EVP_MD_CTX_cleanup(mctx);
    return r;
}

int CMS_SignerInfo_altverify(CMS_SignerInfo *si, BIO *bio_cont) {
    EVP_MD_CTX *mctx = &si->mctx;
    unsigned char *abuf = NULL;
    int alen, r = -1;
    const EVP_MD *md = NULL;
    EVP_PKEY *altpk = NULL;
    int sigind = -1;
    X509_ATTRIBUTE *sigattr = NULL;
    ASN1_OCTET_STRING *sigoct = NULL;
    int default_digest_nid = -1;
    unsigned char *cont = NULL;
    long contlen = 0;


    EVP_MD_CTX_init(mctx);

    altpk = get_SAPKI_from_x509(si->signer);
    if (!altpk) {
        CMSerr(CMS_F_CMS_SIGNERINFO_ALTVERIFY, CMS_R_NO_PUBLIC_KEY);
        goto err;
    }

    sigind = CMS_unsigned_get_attr_by_NID(si, NID_cmsAltSignatureValue, -1);
    if (sigind < 0) {
        goto err;
    }

    sigattr = CMS_unsigned_get_attr(si, sigind);
    if (sigattr == NULL) {
        goto err;
    }

    sigoct = get_ALTSIG_from_ATTRIBUTE(sigattr);
    if (sigoct == NULL) {
        goto err;
    }

    if (CMS_signed_get_attr_count(si) < 0) {
        /* bio_cont is the output from SMIME_read_CMS(). As such it is a store
         * bio that contains the message content that was signed.
         */
        bio_cont = BIO_find_type(bio_cont, BIO_TYPE_STORE);
        if (bio_cont == NULL)
            goto err;

        contlen = BIO_get_store_data(bio_cont, &cont);
        if (contlen <= 0)
            goto err;

    } else {
        alen = ASN1_item_i2d((ASN1_VALUE *)si->signedAttrs, &abuf,
                             ASN1_ITEM_rptr(CMS_Attributes_Verify));

        if (!abuf)
            goto err;

        cont = abuf;
        contlen = alen;
    }

    if ((EVP_PKEY_get_default_digest_nid(altpk, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        r = cms_SignerInfo_rawverify(altpk, cont, contlen, sigoct->data, sigoct->length);
    } else {
        md = EVP_get_digestbyobj(si->digestAlgorithm->algorithm);
        if (md == NULL) {
            goto err;
        }

        if (EVP_DigestVerifyInit(mctx, &si->pctx, md, NULL, altpk) <= 0)
            goto err;

        if (!cms_sd_asn1_ctrl(si, 1))
            goto err;

        r = EVP_DigestVerifyUpdate(mctx, cont, contlen);
        if (r <= 0) {
            r = -1;
            goto err;
        }
        r = EVP_DigestVerifyFinal(mctx, sigoct->data, sigoct->length);
        if (r <= 0)
            CMSerr(CMS_F_CMS_SIGNERINFO_ALTVERIFY, CMS_R_VERIFICATION_FAILURE);
    }

 err:
    if (altpk)
        EVP_PKEY_free(altpk);
    if (abuf)
        OPENSSL_free(abuf);
    EVP_MD_CTX_cleanup(mctx);
    return r;
}

/* Create a chain of digest BIOs from a CMS ContentInfo. Add a store BIO
 * in case we want to do raw signing.
 */
BIO *cms_SignedData_init_bio(CMS_ContentInfo *cms)
{
    int i;
    CMS_SignedData *sd;
    BIO *chain = NULL;
    sd = cms_get0_signed(cms);
    if (!sd)
        return NULL;
    if (cms->d.signedData->encapContentInfo->partial)
        cms_sd_set_version(sd);

    chain = BIO_new(BIO_f_store());
    if (!chain)
        goto err;

    for (i = 0; i < sk_X509_ALGOR_num(sd->digestAlgorithms); i++) {
        X509_ALGOR *digestAlgorithm;
        BIO *mdbio;
        digestAlgorithm = sk_X509_ALGOR_value(sd->digestAlgorithms, i);
        mdbio = cms_DigestAlgorithm_init_bio(digestAlgorithm);
        if (!mdbio)
            goto err;
        BIO_push(chain, mdbio);
    }
    return chain;
 err:
    if (chain)
        BIO_free_all(chain);
    return NULL;
}

int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain)
{
    ASN1_OCTET_STRING *os = NULL;
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pkctx = NULL;
    int r = -1;
    unsigned char mval[EVP_MAX_MD_SIZE];
    unsigned int mlen;
    int default_digest_nid = -1;
    EVP_MD_CTX_init(&mctx);


    if ((CMS_signed_get_attr_count(si) < 0)
        && (EVP_PKEY_get_default_digest_nid(si->pkey, &default_digest_nid) > 0)
        && (default_digest_nid == NID_undef)) {
        /* There are no signed attributes and the pkey did raw signing,
         * so verify against the content. The chain should have a store BIO.
         * Find it and verify against the content of that BIO.
         */
        unsigned char *cont = NULL;
        long contlen = 0;

        chain = BIO_find_type(chain, BIO_TYPE_STORE);
        if (chain == NULL)
            goto err;

        contlen = BIO_get_store_data(chain, &cont);
        if (contlen <= 0)
            goto err;

        if (cms_SignerInfo_rawverify(si->pkey, cont, (size_t)contlen, si->signature->data, si->signature->length) <= 0)
            goto err;

        r = 1;

    } else {
        /* If we have any signed attributes look for messageDigest value */
        if (CMS_signed_get_attr_count(si) >= 0) {
            os = CMS_signed_get0_data_by_OBJ(si,
                                             OBJ_nid2obj(NID_pkcs9_messageDigest),
                                             -3, V_ASN1_OCTET_STRING);
            if (!os) {
                CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                       CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE);
                goto err;
            }
        }

        if (!cms_DigestAlgorithm_find_ctx(&mctx, chain, si->digestAlgorithm))
            goto err;

        if (EVP_DigestFinal_ex(&mctx, mval, &mlen) <= 0) {
            CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                   CMS_R_UNABLE_TO_FINALIZE_CONTEXT);
            goto err;
        }

        /* If messageDigest found compare it */

        if (os) {
            if (mlen != (unsigned int)os->length) {
                CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                       CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH);
                goto err;
            }

            if (memcmp(mval, os->data, mlen)) {
                CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                       CMS_R_VERIFICATION_FAILURE);
                r = 0;
            } else
                r = 1;
        } else {
            const EVP_MD *md = EVP_MD_CTX_md(&mctx);
            pkctx = EVP_PKEY_CTX_new(si->pkey, NULL);
            if (pkctx == NULL)
                goto err;
            if (EVP_PKEY_verify_init(pkctx) <= 0)
                goto err;
            if (EVP_PKEY_CTX_set_signature_md(pkctx, md) <= 0)
                goto err;
            si->pctx = pkctx;
            if (!cms_sd_asn1_ctrl(si, 1))
                goto err;
            r = EVP_PKEY_verify(pkctx, si->signature->data,
                                si->signature->length, mval, mlen);
            if (r <= 0) {
                CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT,
                       CMS_R_VERIFICATION_FAILURE);
                r = 0;
            }
        }
    }
 err:
    if (pkctx)
        EVP_PKEY_CTX_free(pkctx);
    EVP_MD_CTX_cleanup(&mctx);
    return r;

}

int CMS_add_smimecap(CMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs)
{
    unsigned char *smder = NULL;
    int smderlen, r;
    smderlen = i2d_X509_ALGORS(algs, &smder);
    if (smderlen <= 0)
        return 0;
    r = CMS_signed_add1_attr_by_NID(si, NID_SMIMECapabilities,
                                    V_ASN1_SEQUENCE, smder, smderlen);
    OPENSSL_free(smder);
    return r;
}

int CMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs,
                            int algnid, int keysize)
{
    X509_ALGOR *alg;
    ASN1_INTEGER *key = NULL;
    if (keysize > 0) {
        key = ASN1_INTEGER_new();
        if (!key || !ASN1_INTEGER_set(key, keysize))
            return 0;
    }
    alg = X509_ALGOR_new();
    if (!alg) {
        if (key)
            ASN1_INTEGER_free(key);
        return 0;
    }

    X509_ALGOR_set0(alg, OBJ_nid2obj(algnid),
                    key ? V_ASN1_INTEGER : V_ASN1_UNDEF, key);
    if (!*algs)
        *algs = sk_X509_ALGOR_new_null();
    if (!*algs || !sk_X509_ALGOR_push(*algs, alg)) {
        X509_ALGOR_free(alg);
        return 0;
    }
    return 1;
}

/* Check to see if a cipher exists and if so add S/MIME capabilities */

static int cms_add_cipher_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)
{
    if (EVP_get_cipherbynid(nid))
        return CMS_add_simple_smimecap(sk, nid, arg);
    return 1;
}

static int cms_add_digest_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)
{
    if (EVP_get_digestbynid(nid))
        return CMS_add_simple_smimecap(sk, nid, arg);
    return 1;
}

int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap)
{
    if (!cms_add_cipher_smcap(smcap, NID_aes_256_cbc, -1)
        || !cms_add_digest_smcap(smcap, NID_id_GostR3411_94, -1)
        || !cms_add_cipher_smcap(smcap, NID_id_Gost28147_89, -1)
        || !cms_add_cipher_smcap(smcap, NID_aes_192_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_aes_128_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_des_ede3_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 128)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 64)
        || !cms_add_cipher_smcap(smcap, NID_des_cbc, -1)
        || !cms_add_cipher_smcap(smcap, NID_rc2_cbc, 40))
        return 0;
    return 1;
}
