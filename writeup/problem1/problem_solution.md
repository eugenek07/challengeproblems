## Step 1: Environment Setup
- create necessary directories
- venv installation
- venv activate -> install packages

## Step 3: RSA code creation

## Step 4: ECDSA code creation

## Step 5: HKDF code creation

## Step 6: HMAC code creation

## Step 7: AES code creation

## Step 8: Create main.py
- import necessary packages
### Methodology
- Goal: Send root key to receiver
- ECDSA(RSA(rootkey))
- Goal: Create AES, HMAC keys from rootkey
- AES_key, HMAC_key = HKDF(rootkey)
- Goal: Send message to receiver
- HMAC(AES(message))