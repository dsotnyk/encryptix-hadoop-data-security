This is Encryption Module for Hadoop Data Security Project

-----------------------------------------------------------
1. Note on Elliptic Keys generation with OpenSSL
-----------------------------------------------------------

1.2 List available curves
-----------------------------------------------------------

openssl ecparam -list_curves

1.3 Create keys with IMPLICIT curve definition (name only included, size less, but not all libraries may include this curve definition)
-----------------------------------------------------------

# Create params
openssl ecparam -name sect571r1 -out key_params.pem

# Create key pair with private key
openssl ecparam -in key_params.pem -genkey -noout -out key_private.pem

# Create public
openssl ec -in key_private.pem -pubout -out key_public.pem

# Set password (encrypt) to private key
openssl ec -aes-256-cbc -in key_private.pem -out key_private_encrypted.pem

1.4 Create keys with EXPLICIT curve definition (full curve definitionincluded, not only name; size bigger, but any library will be able to use it even when specific curve is not known)
-----------------------------------------------------------

# Create params
openssl ecparam -name sect571r1 -out key_params_explicit.pem -param_enc explicit

# Create key pair with private key
openssl ecparam -in key_params_explicit.pem -genkey -noout -out key_private_explicit.pem

# Create public
openssl ec -in key_private_explicit.pem -pubout -out key_public_explicit.pem

# Set password (encrypt) to private key
openssl ec -aes-256-cbc -in key_private_explicit.pem -out key_private_explicit_encrypted.pem

1.5 [OPTIONAL] Remove password from private key
-----------------------------------------------------------
openssl ec -in key_encrypted.pem  -out key_unencrypted.pem

-----------------------------------------------------------
2. AES Encryption with OpenSSL
-----------------------------------------------------------

openssl aes-256-cbc -in input.txt -out output.txt.aes256

openssl aes-256-cbc -d -in input.txt.aes256 -out output.txt

