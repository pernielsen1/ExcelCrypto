#!/bin/bash
# clean temp directory
rm temp/*
# Create a random IV and store it in AliceIv.base64
IV=`openssl rand -hex 12`
echo -n "$IV"|xxd -r -p>temp/AdvancedAliceIv.bin
openssl base64 -A -in temp/AdvancedAliceIv.bin -out temp/AdvancedAliceIv.base64
# Create a random aesKey encrypt message and store it base64 encoded in AliceReplyEncrypted.base64
AESkey=`openssl rand -hex 32`
# GCM encrypte
oaep_label="426F62"
# oaep_label=""
echo -n "$oaep_label"|xxd -r -p>temp/AdvancedAliceOAEPlabel.bin
openssl base64 -A -in temp/AdvancedAliceOAEPlabel.bin -out temp/AdvancedAliceOAEPlabel.base64

¤ ./openssl_aes_gcm AdvancedAliceReplyEncrypted.plain temp/AdvancedAliceReplyEncrypted.bin "$AESkey" "$IV" e
./openssl_aesgcm AdvancedAliceReplyEncrypted.plain temp/AdvancedAliceReplyEncrypted.bin "$AESkey" "$IV" e

openssl base64 -A -in temp/AdvancedAliceReplyEncrypted.bin -out temp/AdvancedAliceReplyEncrypted.base64
# Now wrap the key by encrypting with Bob's public key with padding mode OAEP and store it in AliceEncryptedKey.base64
echo -n "$AESkey"|xxd -r -c 200 -p>temp/AESkey.bin
pkeyopt="-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_oaep_label:""$oaep_label"" -pkeyopt rsa_mgf1_md:sha256"  
openssl pkeyutl -encrypt -in temp/AESkey.bin --out temp/AdvancedAliceEncryptedKey.bin -pubin -inkey keys/BobPublic.pem $pkeyopt
echo $pkeyopt
openssl base64 -A -in temp/AdvancedAliceEncryptedKey.bin -out temp/AdvancedAliceEncryptedKey.base64
# Finally sign it with private key using sha256 as digest function and store it in AliceReplySignature
openssl dgst -sha256 -sign keys/AlicePrivate.pem -out temp/AdvancedAliceReplySignature.bin AdvancedAliceReplyEncrypted.plain
openssl base64 -A -in temp/AdvancedAliceReplySignature.bin -out temp/AdvancedAliceReplySignature.base64
rm temp/*.bin
echo "Message encrypted and signed send .base64 files from temp"


