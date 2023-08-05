#!/bin/bash
# clean temp directory
rm temp/*
# Decode all base64 files to binary stored in temp directory
openssl base64 -d -in BobIv.base64 -out temp/BobIv.bin
openssl base64 -d -in BobEncrypted.base64 -out temp/BobEncrypted.bin
openssl base64 -d -in BobEncryptedKey.base64 -out temp/BobEncryptedKey.bin
openssl base64 -d -in BobSignature.base64 -out temp/BobSignature.bin
# Decrypt the AESkey using Alice's Private key
openssl pkeyutl -decrypt -in temp/BobEncryptedKey.bin --out temp/BobEncryptedKey.clear -inkey keys/AlicePrivate.pem -pkeyopt rsa_padding_mode:pkcs1
# Convert the BobIV.bin file to variable IV and BobEncryptedKey.bin to variable AESkey and decrypt BobEncrypted.bin to BobEncrypted.plain openssl uses PKCS7 padding by default
IV=`xxd -p temp/BobIv.bin`
AESkey=`xxd -p temp/BobEncryptedKey.clear`
openssl enc -d -aes-128-cbc -in temp/BobEncrypted.bin -out temp/BobEncrypted.plain -K "$AESkey" -iv "$IV" 
# No let us tell about the result
echo "Bob Wrote:"
cat temp/BobEncrypted.plain
echo -e "\nResult of signature verification was:"
# verify the hash calculated with sha256 over the plain message using Bob's public key
openssl dgst -sha256 -verify keys/BobPublic.pem -signature temp/BobSignature.bin temp/BobEncrypted.plain