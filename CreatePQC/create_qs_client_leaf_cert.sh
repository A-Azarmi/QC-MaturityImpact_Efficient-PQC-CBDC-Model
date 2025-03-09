# These scripts will create a hybrid certificate chain. The client certs will be RSA-Dilithium

SUBJECT="/C=IR/ST=Tehran/L=Tehran/O=Unaffiliated/CN=AmirAzarmivar"

export ISARA_VERBOSE=1

# This is the directory where your libiqr_toolkit.so file is located
TOOLKIT_DIR="/opt/HybridCryptography/Thesis/Test/openssl_connector_Linux"

# This is the directory where you built OpenSSL.
OPENSSL_DIR="/opt/HybridCryptography/Thesis/Test/OSSL"

# This is the location of libiqre_engine.so. It would have been extracted from
# the package.
IQRE_ENGINE="/opt/HybridCryptography/Thesis/Test/libiqre_engine.so"

# This is the directory that contains various configuration (.cfg) files
CFG_DIR="/opt/HybridCryptography/Thesis/Test/openssl_connector_Linux/demos"

# This is the directory containing the demos after you've built them
BIN_DIR="/opt/HybridCryptography/Thesis/Test/openssl_connector_Linux/demos"

# This is the location of the demo openssl_tls_server executable that you built.
OPENSSL_TLS_SERVER="${BIN_DIR}/openssl_tls_server"

# This is the location of the demo openssl_tls_client executable that you built.
OPENSSL_TLS_CLIENT="${BIN_DIR}/openssl_tls_client"

# Do not modify.
TLS_DAT_DIR="${BIN_DIR}/tls_demo_data"

# Do not modify.
OPENSSL_APP="${OPENSSL_DIR}/apps/openssl"

#export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
export LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"

set -e

rm -f intermediate/private/client.key.pem 
rm -f intermediate/certs/client.cert.pem 
rm -f intermediate/csr/client.csr.pem
rm -f intermediate/private/dilithium_leaf_private.key.pem
rm -f intermediate/certs/rsa_dilithium_leaf_certificate.pem

set +x
echo "\n\n\n"
echo "--================ Create RSA leaf certificate ================--"
echo ""
set -x

${OPENSSL_APP} genrsa -out intermediate/private/client.key.pem 2048 

#create CSR for client cert
${OPENSSL_APP} req -config intermediate/openssl.cnf \
      -key intermediate/private/client.key.pem \
      -subj ${SUBJECT} \
      -new -sha256 -out intermediate/csr/client.csr.pem 

#Sign the CSR with the Intermediate CA
${OPENSSL_APP} ca -config intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/client.csr.pem \
      -out intermediate/certs/client.cert.pem

chmod 444 intermediate/certs/client.cert.pem

#Verify the client cert
${OPENSSL_APP} x509 -noout -text -in intermediate/certs/client.cert.pem

#Verify the client cert chain of trust
${OPENSSL_APP} verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/client.cert.pem


set +x
echo "\n\n\n"
echo "--================ Create Dilithium private key for ================--"
echo "--================ leaf cert with NIST parameter set A ================--"
set -x

# Dilithium private key for leaf cert with NIST parameter set A
${OPENSSL_APP} genpkey -engine ${IQRE_ENGINE} \
              -algorithm dilithium  \
              -pkeyopt parameter_set:Dilithium_III_SHAKE_r2 \
              -out intermediate/private/dilithium_leaf_private.key.pem

${OPENSSL_APP} pkey -engine ${IQRE_ENGINE} \
              -in intermediate/private/dilithium_leaf_private.key.pem \
              -pubout \
              -out intermediate/private/dilithium_leaf_public.key.pem


set +x
echo "\n\n\n"
echo "--================ Extend the leaf private key ================--"
set -x

# Extend the leaf private key.
python ${BIN_DIR}/privQSExtend.py \
               intermediate/private/client.key.pem \
               intermediate/private/dilithium_leaf_private.key.pem


set +x
echo "\n\n\n"
echo "--================ Create Dilithium-RSA Catalyst leaf certificate ================--"
set -x


# the file intermediate/private/dilithium_intermediate_private.key.pem was modified by the script to 
# create the server leaf certificate. It is now a dual key file, so the intermediate.key.pem file does not 
# need to be passed into this script.  
# Create Dilithium-RSA Catalyst leaf certificate by putting the Dilithium public key directly into RSA leaf certificate.
#${OPENSSL_APP} x509QSDirectExtend -engine ${IQRE_ENGINE} \
#              -x509in intermediate/certs/client.cert.pem \
#              -pubqs intermediate/private/dilithium_leaf2_public.key.pem  \
#              -privin intermediate/private/intermediate.key.pem \
#              -privqs intermediate/private/dilithium_intermediate_private.key.pem \
#              -x509out intermediate/certs/rsa_dilithium_leaf_certificate_2.pem

# Create Dilithium-RSA Catalyst leaf certificate by putting the Dilithium public key directly into RSA leaf certificate.
${OPENSSL_APP} x509QSDirectExtend -engine ${IQRE_ENGINE} \
              -x509in intermediate/certs/client.cert.pem \
              -pubqs intermediate/private/dilithium_leaf_public.key.pem  \
              -privqs intermediate/private/dilithium_leaf_private.key.pem \
              -x509out intermediate/certs/rsa_dilithium_leaf_certificate.pem

# set +x
# echo "\n\n\n"
# echo "--================ Verify certificate chain classically ================--"
# set -x


# # Verify certificate chain classically.
# ${OPENSSL_APP} verify -verbose \
#                -CAfile certs/rsa_hss_root_private.cert.pem \
#                -untrusted intermediate/certs/dilithium_rsa_intermediate.cert.pem \
#                intermediate/certs/rsa_dilithium_leaf_certificate.pem 

set +x
echo "\n\n\n"
echo "--================ Verify certificate chain quantum-safely ================--"
set -x

# Verify certificate chain quantum-safely.
${OPENSSL_APP} x509QSVerify -engine ${IQRE_ENGINE} \
              -root certs/rsa_hss_root_private.cert.pem \
              -untrusted intermediate/certs/dilithium_rsa_intermediate.cert.pem \
              -cert intermediate/certs/rsa_dilithium_leaf_certificate.pem 




set +x
echo "\n\n\n"
echo "--================ Concatenate leaf cert and the intermediate cert ================--"
set -x

# Concatenate leaf cert and the intermediate cert.
MESSAGE_FILE="intermediate/private/partial_certchain_for_server.pem"
cat intermediate/certs/rsa_dilithium_leaf_certificate.pem \
    intermediate/certs/dilithium_rsa_intermediate.cert.pem > ${MESSAGE_FILE}


#Verify the client cert
openssl x509 -noout -text -in intermediate/certs/rsa_dilithium_leaf_certificate.pem