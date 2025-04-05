# Create PQC

This directory contains scripts to create an Quantum safe hybrid certificate chain by using ibiqre_engine

# Hybrid PQC cert inspection

**openssl x509 -in /opt/HybridCryptography/Thesis/certs/HybridPQCcert.pem -text**

    Certificate:

    Data:
    
        Version: 3 (0x2)
        
        Serial Number: 4174 (0x104e)
        
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=IR, ST=Tehran, O=Governmetnal, OU=Central Bank, CN=Central BankIssuer CA
        Validity
            Not Before: Mar 24 20:33:19 2025 GMT
            Not After : Mar 24 20:33:19 2026 GMT
        Subject: C=IR, ST=Tehran, L=Tehran, O=Unaffiliated, CN=Amir Azarmivar
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:dc:3a:18:b6:27:0a:a5:79:be:53:94:00:f3:86:
                    ef:72:d8:c7:87:63:e9:07:99:5a:40:ba:7b:41:e5:
                    03:dd:78:9e:3a:13:ae:fe:61:b0:e8:36:0f:36:f1:
                    83:60:54:d5:1a:c7:07:a5:73:74:67:bd:69:da:08:
                    ba:30:9e:53:e1:0a:95:41:10:de:6e:23:22:e0:f5:
                    9b:ce:85:66:5a:5a:69:7c:95:48:bb:b2:cb:16:87:
                    26:b8:70:1d:7c:7f:a5:31:64:ad:22:9c:29:05:47:
                    5a:6a:d6:96:fc:7c:66:2a:9a:9b:44:cd:dc:49:7f:
                    de:76:c2:ea:47:dc:3d:07:c8:76:18:5f:d8:67:98:
                    6d:fa:77:9a:c9:8e:b3:43:53:73:61:f2:e9:e9:8c:
                    53:9e:cc:83:da:4a:06:70:78:54:61:e2:27:af:1a:
                    da:e8:5a:37:12:55:1a:c0:af:22:82:2a:a9:e3:f4:
                    84:de:8b:cc:50:bc:6c:14:04:9a:9c:03:90:7b:ee:
                    05:3d:49:70:f0:a4:14:9c:55:78:7e:e2:40:1f:d8:
                    da:2c:e8:41:27:9c:48:46:83:b1:08:78:b1:af:fa:
                    a9:3b:07:db:55:4e:ff:b1:10:7d:0b:04:65:70:0d:
                    e1:10:67:e6:02:f9:bb:10:08:60:7e:8a:26:37:85:
                    74:d8:51:41:08:b4:59:00:5f:ca:05:3a:7b:94:52:
                    9e:bc:56:8a:a3:30:46:3b:44:99:ab:8a:0f:bd:1b:
                    94:2c:2f:da:2e:c7:0f:5f:59:56:c4:ed:1c:96:cf:
                    72:80:d4:7e:ec:7f:1e:c9:02:c5:e3:4a:27:a6:c3:
                    cf:92:23:dc:4d:f5:bd:b7:27:35:04:ea:54:e9:39:
                    16:ab:fb:ca:0a:81:9f:8d:a0:db:21:7d:30:cd:79:
                    72:d4:ef:8f:c8:1d:6a:f7:90:f0:ab:d7:b6:77:f6:
                    46:5e:67:e8:d0:df:cf:1d:68:2d:f5:df:e0:5c:cf:
                    92:59:31:74:b9:48:41:cd:00:59:07:84:86:75:bf:
                    a3:3e:55:82:4d:b5:fc:53:4b:b0:b0:04:b8:83:0a:
                    2a:4f:47:8d:0f:d8:44:94:8d:c7:2b:76:bf:6d:a7:
                    72:0d:85:63:a2:b7:17:3b:bf:f1:63:93:fb:c4:c5:
                    ad:0a:e6:fa:df:64:0d:59:0e:3b:f1:09:cc:c4:9a:
                    a0:37:3b:39:68:2d:56:f7:54:37:7b:1a:08:61:96:
                    f6:8e:5f:aa:65:6e:b6:53:19:1b:ab:18:e4:87:ff:
                    76:57:3f:76:4c:34:d2:f5:55:65:95:4c:62:9f:94:
                    90:59:e0:77:06:22:59:7c:61:1e:d4:d5:74:6c:a6:
                    5d:f3:b9
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                A0:FE:A3:38:53:5E:68:18:8E:5C:8A:87:5B:F5:48:F6:55:8E:37:8E
            X509v3 Authority Key Identifier:
                keyid:98:0C:F6:60:9B:F1:80:C6:83:55:F2:E6:E9:F8:56:90:32:C3:14:F3

            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            Alternative Signature Algorithm:
                Hierarchical-Signature-Scheme

            Subject Alternative Public Key:
            
                0...0...................................PA.*,C.EF%8......L....S..9&.q|.......B..B.9.&L....J..s-d

            Alternative Signature Value:
            
                Signature:
                
                    00:00:00:01:00:00:00:00:00:00:00:02:19:fe:21:
                    b3:24:74:e5:c3:78:35:4c:12:76:d2:5c:96:1e:ab:
                    32:84:91:ee:08:0a:6f:ed:c8:ef:d2:5c:d2:2c:bd:
                    a3:81:d2:05:b2:ec:70:ca:e2:57:b0:b4:44:79:a5:
                    a5:db:5b:b9:b7:b6:97:85:11:38:98:43:ca:4e:8f:
                    99:b5:03:ea:27:2b:2a:9d:f6:5e:ba:9e:21:58:76:
                    a8:84:71:86:23:c5:5d:b4:58:2b:ae:a2:3e:a8:bc:
                    ce:12:c6:03:7c:4b:69:81:66:64:05:2f:29:69:af:
                    0f:45:b8:b7:37:a4:be:e4:dc:42:14:5e:0d:e8:7c:
                    90:13:08:3e:86:cc:9d:a3:ac:8c:ac:3c:f9:e5:ad:
                    cf:aa:2d:bb:fd:a9:36:ae:cf:b1:14:5d:2c:ad:08:
                    69:b6:5e:41:8a:fc:ae:c3:c8:4f:8d:c4:9b:72:27:
                    57:20:56:b9:2e:5b:ae:5e:8f:2e:65:b2:11:f4:6a:
                    e0:f9:62:52:8d:3e:c1:5e:eb:04:85:b3:05:c4:2f:
                    34:89:cf:ed:1b:dc:7b:eb:c3:8d:14:b5:85:99:fd:
                    58:16:4c:2a:16:e1:c8:b5:0b:4e:1f:e3:09:ef:df:
                    95:e0:d5:f3:8b:89:b8:18:22:7a:2c:5e:60:9e:45:
                    6d:92:55:6c:a9:45:6f:80:aa:b5:8c:53:62:f2:f3:
                    63:2b:ec:bf:ed:0e:b5:a0:48:47:b9:24:b2:3e:36:
                    5a:9c:dd:a1:af:46:34:7f:1a:62:b7:70:27:b5:e6:
                    0a:d4:17:00:10:6e:38:43:52:a0:d1:66:78:3f:ae:
                    24:fa:8b:33:90:cd:48:03:39:6d:41:fc:da:10:29:
                    77:f8:0b:00:3f:f7:cf:c9:49:e5:04:32:ee:69:fd:
                    d4:39:35:90:0b:14:e9:34:9c:9c:ff:9c:c2:4a:f8:
                    6f:7d:cc:6f:dc:6a:49:d0:6d:bb:23:e3:83:55:13:
                    9a:99:fd:b1:b8:f1:1b:b7:7d:35:dc:1c:ba:dd:3f:
                    2f:41:0a:b6:90:f9:79:03:c1:64:f6:be:a8:fc:53:
                    06:31:3f:c5:f5:04:f1:a4:64:1a:10:15:7c:ad:af:
                    5b:44:a2:3b:47:d7:e3:9f:3b:94:55:2a:e2:53:08:
                    f8:53:5e:4a:90:7e:2f:76:56:82:ac:b9:13:bd:4a:
                    be:0f:6b:e3:a8:8a:cf:09:b5:2d:d9:43:03:3b:ea:
                    98:a5:41:7d:ce:71:64:69:43:93:3b:ed:f6:00:af:
                    40:a0:cb:88:5b:46:d6:6c:d8:96:ef:76:cb:b0:8e:
                    7e:36:a1:fd:af:54:b7:b0:1d:cf:48:ef:f1:e0:d4:
                    92:d1:8b:ae:a3:27:f3:ac:7c:20:1c:d9:e8:e9:8e:
                    dd:97:82:ef:8b:ac:b4:ab:bc:20:b1:e9:8b:c2:65:
                    ed:07:45:68:5c:47:f7:be:c7:1d:2b:14:60:e4:39:
                    72:a5:98:e1:72:1b:93:9e:40:79:63:a6:19:bf:b8:
                    28:fb:f1:d8:c9:c0:31:87:12:c0:a4:78:3e:cf:02:
                    7a:9b:f1:5a:08:a3:19:f0:26:05:ae:8d:9c:33:c6:
                    6d:f5:4e:4b:3d:dd:42:6b:2b:f7:48:b1:d9:c5:cc:
                  

                  Signature Algorithm: sha256WithRSAEncryption
                  
                 02:53:4a:41:d8:01:05:ef:81:94:df:a4:a1:3a:89:14:47:3a:
                 b8:4d:57:19:47:d3:b7:c1:46:d1:e7:67:b9:49:58:66:a4:85:
                 c7:2d:5b:7a:0c:87:64:71:49:73:5a:7d:f6:48:e0:40:67:97:
                 37:1d:b1:b7:e6:ee:9e:73:f9:51:62:2c:32:d3:b8:5f:44:5c:
                 eb:e1:e3:a7:a9:6a:13:4b:bc:da:95:8a:15:ea:69:e7:9e:50:
                 6e:73:08:32:5d:b6:8d:eb:05:93:68:7b:91:38:f5:60:c9:3b:
                 5f:7e:30:2c:48:c0:ed:8c:9f:25:bd:3f:0d:10:55:2c:01:e4:
                 a8:b5:13:59:02:54:d2:15:82:d5:f6:94:4d:77:d0:69:96:5a:
                 06:d3:9e:19:14:c1:9d:ea:79:9b:4c:24:83:e0:fa:a8:e5:10:
                 d5:0b:7f:b2:83:6f:e4:e6:f9:39:61:95:1c:c6:07:dd:3d:b9:
                 46:d2:ea:9f:a0:65:f9:93:45:fd:b0:eb:cc:23:20:9a:c2:61:
                 60:b6:8e:91:77:22:64:4e:b9:fa:0e:6b:70:6b:3d:c1:b7:93:
                 68:d2:70:af:c8:4b:fe:54:3d:00:a5:75:3b:7c:8d:53:f4:23:
                 c2:dd:76:8f:68:66:32:a0:0f:9d:7d:a6:71:12:24:86:d6:d5:
                 dc:f8:15:a2:6d:34:fb:2c:f3:ee:5a:f1:ba:0c:fa:1c:39:6e:
                 eb:f9:71:b8:a2:ae:14:d6:bb:8f:e0:f9:ef:17:56:50:02:e6:
                 e3:c3:d3:a5:be:66:c3:22:d0:a0:d4:31:5a:ad:04:29:21:1a:
                 2d:a2:e8:73:50:a5:94:1b:00:28:4f:38:91:0f:23:da:8a:56:
                 7b:28:fd:a4:92:95:ee:d1:c8:e8:74:50:af:50:fc:39:d5:79:
                 07:b4:d0:ba:d7:a1:44:22:37:61:22:be:49:ab:9d:e1:0e:5c:
                 e8:ea:d7:5e:e0:6d:24:38:5d:6b:a5:a0:43:b4:75:8c:91:d8:
                 f7:b9:87:c7:0d:38:3e:f7:f8:b3:38:3c:62:a9:6d:2d:99:d4:
                 f0:7d:13:4f:3b:a6:57:10:a1:8a:35:33:64:87:3f:84:88:d0:
                 3b:9d:b9:54:23:79:71:67:d5:d6:de:f0:5f:db:d2:64:ae:34:
                 e9:52:61:b2:1e:98:9d:20:7e:07:91:be:b3:07:cf:d3:68:07:
                 71:67:6a:a1:1e:72:31:09:2a:20:bb:cc:48:3a:00:e1:e3:80:
                 3d:f5:19:2e:b5:10:d0:41:14:3c:8d:30:80:86:b0:d9:a9:3c:
                 2d:3f:67:49:6e:81:c9:7e:25:a5:20:89:dd:2f:31:34:9d:ee:
                 57:e0:93:08:10:a3:a2:d7
