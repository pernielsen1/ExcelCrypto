#!/bin/bash
# clean temp directory
rm temp/*
# Decode all base64 files to binary stored in temp directory
openssl base64 -d -in EC_BobIv.base64 -out temp/EC_BobIv.bin
openssl base64 -d -in EC_BobAppend.base64 -out temp/EC_BobAppend.bin
openssl base64 -d -in EC_BobEncrypted.base64 -out temp/EC_BobEncrypted.bin
openssl base64 -d -in EC_BobSignature.base64 -out temp/EC_BobSignature.bin
#------------------------------------------------------------
# derive the shared secret
#------------------------------------------------------------
openssl pkeyutl -derive -inkey  keys/AlicePrivate.pem -peerkey keys/BobPublic.pem -out temp/shared_secret.bin
shared_secret=`xxd -p temp/shared_secret.bin`
echo "shared_secret:""$shared_secret"
#--------------------------------------------------------------------------
# generate the key according to NIST
# The integer 00000001 + shared secret + EC_BobAppend calculate a sha256
#-------------------------------------------------------------------------
EC_BobAppend=`xxd -p temp/EC_BobAppend.bin`
message="00000001""$shared_secret""$EC_BobAppend"
echo "message:""$message"
echo "$message" | xxd -r -p>temp/message.bin
openssl dgst -sha256 -binary temp/message.bin>temp/AESkey.bin
AESkey=` xxd  -p -c 200 temp/AESkey.bin`
echo "AESkey:" "$AESkey"
# Convert the EC_BobIV.bin file to variable IV decrypt EC_BobEncrypted.bin to EC_BobEncrypted.plain openssl uses PKCS7 padding by default
IV=`xxd -p temp/EC_BobIv.bin`
openssl enc -d -aes-256-cbc -in temp/EC_BobEncrypted.bin -out temp/EC_BobEncrypted.plain -K "$AESkey" -iv "$IV" 
# No let us tell about the result
echo "Bob Wrote:"
cat temp/EC_BobEncrypted.plain
echo -e "\nResult of signature verification was:"
# verify the hash calculated with sha256 over the plain message using Bob's public key
openssl dgst -sha256 -verify keys/BobPublic.pem -signature temp/EC_BobSignature.bin temp/EC_BobEncrypted.plain
