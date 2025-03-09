#
IQRE_ENGINE="/opt/HybridCryptography/CA/Test/libiqre_engine.so"

OPENSSL_DIR="/opt/HybridCryptography/CA/Test/OSSL"

TOOLKIT_DIR="/opt/HybridCryptography/CA/Test/openssl_connector_Linux"

BIN_DIR="/opt/HybridCryptography/CA/Test/openssl_connector_Linux/demos"

# This is the location of the demo openssl_tls_server executable that you built.
OPENSSL_TLS_SERVER="${BIN_DIR}/openssl_tls_server"

# This is the location of the demo openssl_tls_client executable that you built.
OPENSSL_TLS_CLIENT="${BIN_DIR}/openssl_tls_client"

# Do not modify.
TLS_DAT_DIR="${BIN_DIR}/tls_demo_data"


set +x
echo ""
echo ""
echo "--================ Test TLS client/server exchange #1 ================--"
echo ""
set -x
# Perform client-server secure handshake and then secure communication.
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_SERVER} -engine ${IQRE_ENGINE} -cert intermediate/certs/rsa_dilithium_leaf_certificate_1.pem -key intermediate/private/dilithium_leaf1_private.key.pem -keyform PEM -message ${TLS_DAT_DIR}/server_msg.txt & SERVER_PID=$!
sleep 2
set +x
echo ""
echo ""
echo "--================ Start TLS client  ================--"
echo ""
set -x
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_CLIENT} -engine ${IQRE_ENGINE} -ca_cert intermediate/certs/hybrid-ca-chain.cert.pem -message ${TLS_DAT_DIR}/client_msg.txt

wait $SERVER_PID

set +x
echo ""
echo ""
echo "--================ Test TLS client/server exchange #2 using cipher SIKE-RSA-AES256-GCM-SHA384 ================--"
echo ""
set -x

# Perform client-server secure handshake and then secure communication.
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_SERVER} -engine ${IQRE_ENGINE} -cert intermediate/certs/rsa_dilithium_leaf_certificate_1.pem -key intermediate/private/dilithium_leaf1_private.key.pem -keyform PEM -message ${TLS_DAT_DIR}/server_msg.txt & SERVER_PID=$!
sleep 2
set +x
echo ""
echo ""
echo "--================ Start TLS client  ================--"
echo ""
set -x
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_CLIENT} -engine ${IQRE_ENGINE} -ca_cert intermediate/certs/hybrid-ca-chain.cert.pem -cipher 'SIKE-RSA-AES256-GCM-SHA384' -message ${TLS_DAT_DIR}/client_msg.txt
wait $SERVER_PID


set +x
echo ""
echo ""
echo "--================ Test TLS client/server exchange #3 using Mutual Authentication ================--"
echo ""
set -x
# Perform client-server secure handshake and then secure communication.
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_SERVER} -engine ${IQRE_ENGINE} -cert intermediate/certs/rsa_dilithium_leaf_certificate_1.pem -key intermediate/private/dilithium_leaf1_private.key.pem -keyform PEM -ca_cert intermediate/certs/hybrid-ca-chain.cert.pem -client_auth -message ${TLS_DAT_DIR}/server_msg.txt & SERVER_PID=$!
sleep 2
set +x
echo ""
echo ""
echo "--================ Start TLS client  ================--"
echo ""
set -x
LD_LIBRARY_PATH=${OPENSSL_DIR}:${TOOLKIT_DIR}/lib ${OPENSSL_TLS_CLIENT} -engine ${IQRE_ENGINE} -cert intermediate/certs/rsa_dilithium_leaf_certificate_2.pem -key intermediate/private/dilithium_leaf2_private.key.pem -keyform PEM  -ca_cert intermediate/certs/hybrid-ca-chain.cert.pem -message ${TLS_DAT_DIR}/client_msg.txt

wait $SERVER_PID



