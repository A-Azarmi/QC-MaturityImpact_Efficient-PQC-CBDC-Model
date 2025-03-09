"""

Usage: python privQSExtend.py <classical.pem> <quantum_safe.pem>

The classical and quantum-safe PEM files will be read and contents will be
combined into the quantum-safe PEM file. This is only compatible with the
QSExtend utilities when an extended private key is expected. Normal OpenSSL
utilities will simply interpret the extended private key as a classical
private key.

"""
import sys

replacements = {
    "-----BEGIN PRIVATE KEY-----\n": "-----BEGIN ALT PRIVATE KEY-----\n",
    "-----END PRIVATE KEY-----\n": "-----END ALT PRIVATE KEY-----\n",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n": "-----BEGIN ENCRYPTED ALT PRIVATE KEY-----\n",
    "-----END ENCRYPTED PRIVATE KEY-----\n": "-----END ENCRYPTED ALT PRIVATE KEY-----\n",
}

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python privQSExtend.py <classical.pem> <quantum_safe.pem>")
        sys.exit()

    classical = sys.argv[1]
    quantum_safe = sys.argv[2]

    with open(classical, "r") as f:
        classical = f.readlines()

    with open(quantum_safe, "r") as f:
        qs = f.readlines()
        qs = [replacements.get(x, x) for x in qs]

    with open(quantum_safe, "w") as f:
        f.writelines(classical + qs)
