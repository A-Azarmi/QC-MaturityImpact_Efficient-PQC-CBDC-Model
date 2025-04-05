# DKG crypto mechanism in multiSig transactions 

![alt text](DKG.png "DKG")

Alternatively, you can run the code directly in an online SageMath terminal by clicking the following link: 
[Run Online](https://sagecell.sagemath.org/?z=eJylV1tv2zYUfg-Q_3DqPkRKPCHpsD0Y8IAu2Yqi2xCsxV5SQ5AlyuYqkYZEpckC__edQ-pC0nQaoIJh2dI537l_JMtG1qAed1xsgNc72Sj4g7dqDjc8x-9P3a5ipyf9myYThaxPT0pS2mbttuLrQavdZm9--vn05PQkr7K2hX9Yw0uerSt28-Hd4vQE8CpYCWnKBVdpGrWsKucgFsAFGlL9fZc1iud8lwnVLrQrd61qVnGPQBcpJgKWILxnCp8p75mNh6_tv75kw-8zxVIMpGFomxJAtufGC_RutUKEp72v160rngfUpl9HdXNZ11zVTAf7UoN11irWpL3dL-wRhf6Sgk1iU7Yp1zyr-H9M59tO42w2ez--BbVlsGukkrmsoJQNZFXlZAvFJ13MlVDRpE_dg2UeEZIkmcWTOOFZWOjVYXEsz7QFWVFcWizdMMEaqg09FbJGm1HsygdKeGfBUyJJOaBk1cDXMNbzrMq7inAt0YjQgj7Y7fAtQEdYQzoT4OGbrJezWyuVT5b43ip3AV-52sKUsAWK4p891cWaxlBqdafAD79Mfei2zbtep-cDywjIEmE3DcOGurhyWqZhqmsE3BmdhG4UzdUcri4vY90iKTUGvtiYZk1UvDL6lr_hYhgusYMdXX8ukOsBDFpksYqBhak9KlgtBY5kprgUwXAe4BzeaNkH8n5y4TnX3bI_4_wc5FfM9QLQBx2IyynHojH4YPC1cxLnuzk-z72kSzZ6al8yq7xEuVfL3lf3HV2vwUo0WYKuJcawIM9aEF2NSwYmCd7fHGJYsikvhlGynUq4KNhDtIvhAq4OAYxh1OvqKJesLLFwkYsan59zONQcL0oIn4PRxrww7TJGFU3Fi-MjppELNAPQ74M2MhJ-x9zTEvpot4nH33qNfTyg6rMeL0TZn4VRovwbKY-rESy9RwqhHH9qOvZdLD4AGd7T_0Z-TutMbaNvs91HXTi95fDIroWnM415Ri1obLGqZXDGhXm-n3mgdnTTb-Qio-4voXQh9Ci5CBA-EdGai2HV8RemIYzP4k-9bsOtGc4P7BEpObygO25TRP7iONTyvYlzmN-CKZYrVmCPZkJIBQO7gzEBiD1AW8QUqktPSlO-Jw5aS1m5ffjRsGePg1RJ64AZOAJj-MXzNsSfU4fZROkmNND410bCIzolaQNSdLkTb3AIDAANgZ1AbxR6P6hXLkOd8Rp-x5FgWb61EzUnihlcaljO-D1C6P7VLNx-10QNgOlI2XcrV4JAW4Zc2LwEr-_wXuGVs0PWcxH0z9njGN1VADjgcJLtdigfHcdx9kzeMB2sOx56wAcsxpQrIn9PJcDXw8i-LYqJJnVeHQKi8R3BD5iGrrGBLpaWH6FWOrqxN8eqCGcvGtDihIlcFiyK42TLHgq-Ya2KDsa66UQ67MdDM_R3J_SuH2FxeNW0_Xd3BuSYdYqIvVfuGqX3lpwOeSKrWZrCcgmzFBmFizSd9fa9I9nd7C2Gy2ZzmP0q13S7RrCK6yc32b2-_4a3vs_p5FcxYa8cQxHpAPijnYdxDVEk3B9S9Mb4SexdRyK1xQi2siqWT2ofD-XsGePWniByCD_Jv5J7brhF-LJBf5xzcCTwpOsecuNROHEqFv8PNIu2Mw==&lang=python&interacts=eJyLjgUAARUAuQ==)


# Protocol Steps Explanation:

**1. Initialization**

* Create a DKG instance with 5 participants and threshold of 3

* Print startup message with participant names

**2. Participant Setup**

* For each participant:

* Generate a random polynomial of degree t+1 (degree 2 in this case)

* Store the polynomial as private shares

* Calculate simple commitments (just for demonstration)

* Calculate public shares for all other participants

* Print the generated polynomial

**3. Share Verification**

* Verify each participant's shares (in this simple version, always returns True)

* Print validation status for each participant

**4. Share Combination**

* For each participant:

* Collect all shares received from other participants

* Sum the received shares

* Print the sum for each participant

* Combine all sums into a master value

* Generate SHA-256 hash of the combined value as the master public key

**5. Output**

* Print the final master public key (SHA-256 hash of combined shares)

# Key Components

**1. Polynomial Generation**

* Each participant creates a random polynomial where:

* The constant term is their secret share

* Degree determines the threshold (t+1)

**2. Share Distribution**

* Each participant evaluates their polynomial at points corresponding to other participants

* Sends these evaluated points as shares to others

**3. Verification**

* In a real implementation, would verify using cryptographic proofs

* This demo skips real verification for simplicity

**3. Key Reconstruction**

* Combines valid shares using Lagrange interpolation (simplified here)

* Produces a master key that requires threshold+1 participants to reconstruct
