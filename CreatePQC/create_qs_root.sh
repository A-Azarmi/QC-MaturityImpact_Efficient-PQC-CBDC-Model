# The scripts will create a hybrid certificate chain. The certs will be HSS-RSA Root CA

SUBJECT="/C=IR/ST=Tehran/L=Tehran/O=Governmetnal/OU=CentralBank/CN=CentralBankRootCA"

# Remove the next line to turn off verbose messages from the IQRE Engine
export ISARA_VERBOSE=1


# This is the directory where your libiqr_toolkit.so file is located
TOOLKIT_DIR="/opt/HybridCryptography/Thesis/Test/openssl_connector_Linux"

# This is the directory where you built OpenSSL.
OPENSSL_DIR="/opt/HybridCryptography/Thesis/Test/OSSL"

# This is the location of libiqre_engine.so
IQRE_ENGINE="/opt/HybridCryptography/Thesis/Test/libiqre_engine.so"

#export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
export LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
OPENSSL_APP="${OPENSSL_DIR}/apps/openssl"
set -e

rm -f  private/ca.key.pem
rm -f  private/hss_root_private.key.pem
rm -f  index.txt
touch index.txt

set +x
echo "\n\n\n"
echo "--================ Create RSA root certificate ================--"
echo ""
set -x

# Generate RSA key
${OPENSSL_APP} genrsa -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

# Generate an RSA certificate
${OPENSSL_APP} req -config openssl.cnf \
        -key private/ca.key.pem \
        -subj ${SUBJECT} \
        -new -x509 -days 3650 -sha256 -extensions v3_ca \
        -out certs/ca.cert.pem

#Validate the RSA cert
${OPENSSL_APP} x509 -noout -text -in certs/ca.cert.pem

set +x
echo "\n\n\n"
echo "--================ Convert the RSA root certificate to a hybrid ================--"
echo "--================ HSS-RSA catalyst root certificate ================--"
echo ""
set -x


#Generate HSS key
${OPENSSL_APP} genpkey -engine ${IQRE_ENGINE} -algorithm hss -pkeyopt optimization:fast -pkeyopt sign_operations:2E30 -pkeyopt strategy:full -pkeyopt state_filename:private/hss_root_private_key_state.bin -out private/hss_root_private.key.pem

${OPENSSL_APP} pkey -engine ${IQRE_ENGINE} -in private/hss_root_private.key.pem -pubout -out private/hss_root_public.key.pem

#Convert the RSA cert to a Catalyst hybrid cert
${OPENSSL_APP} x509QSDirectExtend -engine ${IQRE_ENGINE} \
        -x509in certs/ca.cert.pem \
        -pubqs private/hss_root_public.key.pem \
        -privin private/ca.key.pem \
        -privqs private/hss_root_private.key.pem::private/hss_root_private_key_state.bin \
        -privqs_engine \
        -x509out certs/rsa_hss_root_private.cert.pem
     

#Validate the quantum safe cert as an X509 cert 
${OPENSSL_APP} x509 -noout -text -in certs/rsa_hss_root_private.cert.pem



