#!/bin/bash
# Create the message
echo "Hi Bob yes EC worked will come for dinner at 7 pm">EC_AliceReply.plain
# clean temp directory
rm temp/*
# Create a random IV and store it in AliceIv.base64
iv=`openssl rand -hex 16`
echo -n "$iv"|xxd -r -p>temp/EC_AliceIv.bin
openssl base64 -A -in temp/EC_AliceIv.bin -out temp/EC_AliceIv.base64
# create an append message "BobAlice" and create  
echo  "BobAlice">temp/EC_AliceAppend.bin
openssl base64 -A -in temp/EC_AliceAppend.bin -out temp/EC_AliceAppend.base64
#------------------------------------------------------------
# derive the shared secret
#------------------------------------------------------------
openssl pkeyutl -derive -inkey  keys/AlicePrivate.pem -peerkey keys/BobPublic.pem -out temp/shared_secret.bin
shared_secret=`xxd -p temp/shared_secret.bin`
echo "shared_secret:""$shared_secret"
#--------------------------------------------------------------------------
# generate the key according to NIST
# The integer 00000001 + shared secret + EC_AliceAppend calculate a sha256
#-------------------------------------------------------------------------
EC_AliceAppend=`xxd -p temp/EC_AliceAppend.bin`
message="00000001""$shared_secret""$EC_AliceAppend"
echo "message:""$message"
echo "$message" | xxd -r -p>temp/message.bin
openssl dgst -sha256 -binary temp/message.bin>temp/AESkey.bin
AESkey=` xxd  -p -c 200 temp/AESkey.bin`
echo "AESkey:" "$AESkey"
openssl enc -e -aes-256-cbc -in EC_AliceReply.plain -out temp/EC_AliceReplyEncrypted.bin -K $AESkey -iv $iv
openssl base64 -A -in temp/EC_AliceReplyEncrypted.bin -out temp/EC_AliceReplyEncrypted.base64
# Finally sign it with private key using sha256 as digest function and store it in AliceReplySignature
openssl dgst -sha256 -sign keys/AlicePrivate.pem -out temp/EC_AliceReplySignature.bin EC_AliceReply.plain
openssl base64 -A -in temp/EC_AliceReplySignature.bin -out temp/EC_AliceReplySignature.base64
rm temp/*.bin
echo "Message encrypted and signed send .base64 files from temp"