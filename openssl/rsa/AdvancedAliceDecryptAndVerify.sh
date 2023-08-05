#!/bin/bash
# clean temp directory
rm temp/*
# Decode all base64 files to binary stored in temp directory
openssl base64 -d -in AdvancedBobIv.base64 -out temp/AdvancedBobIv.bin
openssl base64 -d -in AdvancedBobEncrypted.base64 -out temp/AdvancedBobEncrypted.bin
openssl base64 -d -in AdvancedBobOAEPlabel.base64 -out temp/AdvancedBobOAEPlabel.bin
openssl base64 -d -in AdvancedBobEncryptedKey.base64 -out temp/AdvancedBobEncryptedKey.bin
openssl base64 -d -in AdvancedBobSignature.base64 -out temp/AdvancedBobSignature.bin

# Decrypt the AESkey using Alice's Private key
oaep_label=`xxd -p -c 20000 temp/AdvancedBobOAEPlabel.bin`
pkeyopt="-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_oaep_label:""$oaep_label"" -pkeyopt rsa_mgf1_md:sha256"  
openssl pkeyutl -decrypt -in temp/AdvancedBobEncryptedKey.bin --out temp/AdvancedBobEncryptedKey.clear -inkey keys/AlicePrivate.pem $pkeyopt
# Convert the AdvancedBobIV.bin file to variable IV and AdvancedBobEncryptedKey.bin to variable AESkey and decrypt AdvancedBobEncrypted.bin to BobEncrypted.plain openssl uses PKCS7 padding by default
IV=`xxd -p -c 20000 temp/AdvancedBobIv.bin`
AESkey=`xxd -p -c 20000 temp/AdvancedBobEncryptedKey.clear`
# ./openssl_aes_gcm temp/AdvancedBobEncrypted.bin temp/AdvancedBobEncrypted.plain "$AESkey" "$IV" d
./openssl_aesgcm temp/AdvancedBobEncrypted.bin temp/AdvancedBobEncrypted.plain "$AESkey" "$IV" d

# Now let us tell about the result
echo "Bob Wrote:"
cat temp/AdvancedBobEncrypted.plain
echo -e "\nResult of signature verification was:"
# verify the hash calculated with sha256 over the plain message using Bob's public key
openssl dgst -sha256 -verify keys/BobPublic.pem -signature temp/AdvancedBobSignature.bin temp/AdvancedBobEncrypted.plain
