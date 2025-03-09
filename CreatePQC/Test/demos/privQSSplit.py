"""
@file privQSSplit.py Split an extend private key into a classical private key
                     and QS private key.

Usage: python privQSSplit.py <classical.pem> <quantum_safe.pem>

The quantum-safe PEM file will be read and contents will be split into two
files.  The first private key will be written to the  classical PEM file name
and the quantum-safe PEM file will be over-written with the quantum-safe key.
This is only compatible with Extended private keys created by the QSExtend
utilities.

@copyright Copyright (C) 2018-2019, ISARA Corporation, All Rights Reserved.
"""
import sys

classical_headers = ["-----BEGIN PRIVATE KEY-----\n"]
quantum_safe_headers = ["-----BEGIN ALT PRIVATE KEY-----\n", "-----BEGIN ENCRYPTED ALT PRIVATE KEY-----\n"]

replacements = {
    "-----BEGIN ALT PRIVATE KEY-----\n": "-----BEGIN PRIVATE KEY-----\n",
    "-----END ALT PRIVATE KEY-----\n": "-----END PRIVATE KEY-----\n",
    "-----BEGIN ENCRYPTED ALT PRIVATE KEY-----\n": "-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
    "-----END ENCRYPTED ALT PRIVATE KEY-----\n": "-----END ENCRYPTED PRIVATE KEY-----\n",
}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python privQSSplit.py <classical.pem> <quantum_safe.pem>")
        sys.exit()

    classical = sys.argv[1]
    quantum_safe = sys.argv[2]

    with open(quantum_safe, "r") as f:
        hybrid = f.readlines()

    classical_key = []
    quantum_safe_key = []
    is_qs_section = False
    for line in hybrid:
        if line in classical_headers:
            is_qs_section = False
        elif line in quantum_safe_headers:
            is_qs_section = True

        if is_qs_section:
            quantum_safe_key.append(replacements.get(line, line))
        else:
            classical_key.append(line)

    with open(classical, "w") as f:
        f.writelines(classical_key)

    with open(quantum_safe, "w") as f:
        f.writelines(quantum_safe_key)
