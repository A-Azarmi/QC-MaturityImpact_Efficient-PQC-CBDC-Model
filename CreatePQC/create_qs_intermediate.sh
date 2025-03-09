

# These scripts will create a hybrid intermediate certificate chain under the RootCA. The certs will be RSA-Dilithium

SUBJECT="/C=IR/ST=Tehran/L=Tehran/O=Governmetnal/OU=CentralBank/CN=CentralBankIssuerCA"

export ISARA_VERBOSE=1

# This is the directory where your libiqr_toolkit.so file is located
TOOLKIT_DIR="/opt/HybridCryptography/Thesis/Test/openssl_connector_Linux"

# This is the directory where you built OpenSSL
OPENSSL_DIR="/opt/HybridCryptography/Thesis/Test/OSSL"

# This is the location of libiqre_engine.so
IQRE_ENGINE="/opt/HybridCryptography/Thesis/Test/libiqre_engine.so"

#export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
export LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
OPENSSL_APP="${OPENSSL_DIR}/apps/openssl"

set -e

rm -f intermediate/private/intermediate.key.pem
rm -f intermediate/certs/ca-chain.cert.pem
rm -f intermediate/certs/intermediate.cert.pem 
rm -f intermediate/index.txt
touch intermediate/index.txt


set +x
echo "\n\n\n"
echo "--================ Create RSA intermediate certificate ================--"
echo ""
set -x


# Generate RSA key
${OPENSSL_APP} genrsa -out intermediate/private/intermediate.key.pem 4096
chmod 400 intermediate/private/intermediate.key.pem

set +x
echo "\n\n\n"
echo "--================ Create CSR for RSA intermediate certificate ================--"
echo ""
set -x
${OPENSSL_APP} req -config intermediate/openssl.cnf \
              -new -sha256 \
              -subj ${SUBJECT} \
              -key intermediate/private/intermediate.key.pem \
              -out intermediate/csr/intermediate.csr.pem 


set +x
echo "\n\n\n"
echo "--================ Create RSA intermediate certificate ================--"
echo ""
set -x
# Generate an RSA certificate
${OPENSSL_APP} ca -config openssl.cnf -extensions v3_intermediate_ca \
              -days 365 -notext -md sha256 \
              -in intermediate/csr/intermediate.csr.pem \
              -out intermediate/certs/intermediate.cert.pem 


set +x
echo "\n\n\n"
echo "--================ Validate RSA intermediate certificate ================--"
echo ""
set -x
#Validate the RSA cert
${OPENSSL_APP} x509 -noout -text -in intermediate/certs/intermediate.cert.pem
${OPENSSL_APP} verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

set +x
echo "\n\n\n"
echo "--================ Create RSA intermediate cert chain ================--"
echo ""
set -x

cat  intermediate/certs/intermediate.cert.pem \
     certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem


set +x
echo "\n\n\n"
echo "--================ Generate Dilithium key for intermediate ================--"
echo "--================ cert with NIST parameter set B ================--"
echo ""
set -x
# Dilithium key for intermediate cert with NIST parameter set B
${OPENSSL_APP} genpkey -engine ${IQRE_ENGINE} \
              -algorithm dilithium -pkeyopt \
               parameter_set:Dilithium_IV_SHAKE_r2 \
              -out intermediate/private/dilithium_intermediate_private.key.pem

${OPENSSL_APP} pkey -engine ${IQRE_ENGINE} \
              -in intermediate/private/dilithium_intermediate_private.key.pem \
              -pubout \
              -out intermediate/private/dilithium_intermediate_public.key.pem





set +x
echo "\n\n\n"
echo "--================ Convert the RSA root certificate to a hybrid ================--"
echo "--================ HSS-Dilithium catalyst intermediate certificate ================--"
echo ""
set -x


#Convert the RSA cert to a Catalyst hybrid cert
${OPENSSL_APP} x509QSDirectExtend -engine ${IQRE_ENGINE} \
        -x509in intermediate/certs/intermediate.cert.pem \
        -pubqs intermediate/private/dilithium_intermediate_public.key.pem \
        -privin private/ca.key.pem \
        -privqs private/hss_root_private.key.pem::private/hss_root_private_key_state.bin \
        -privqs_engine \
        -x509out intermediate/certs/dilithium_rsa_intermediate.cert.pem

     
#Validate the quantum cert as an X509 cert 
${OPENSSL_APP} x509 -noout -text -in intermediate/certs/dilithium_rsa_intermediate.cert.pem

# Verify certificate chain quantum-safely.
${OPENSSL_APP} x509QSVerify -engine ${IQRE_ENGINE} \
              -root certs/rsa_hss_root_private.cert.pem \
              -cert intermediate/certs/dilithium_rsa_intermediate.cert.pem  



set +x
echo "\n\n\n"
echo "--================ Create hybrid intermediate cert chain ================--"
echo ""
set -x

cat  intermediate/certs/dilithium_rsa_intermediate.cert.pem \
     certs/rsa_hss_root_private.cert.pem > intermediate/certs/hybrid-ca-chain.cert.pem

