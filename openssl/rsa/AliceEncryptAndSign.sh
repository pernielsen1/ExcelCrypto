#!/bin/bash
# clean temp directory
rm temp/*
# Create a random IV and store it in AliceIv.base64
#aesKey="C1C2C3C4C5C6C7C81C2C3C4C5C6C7C8CA1A2A3A4A5A6A7A81A2A3A4A5A6A7A8A"
#iv="00000000000000000000000000000000"
iv=`openssl rand -hex 16`
echo -n "$iv"|xxd -r -p>temp/AliceIv.bin
openssl base64 -A -in temp/AliceIv.bin -out temp/AliceIv.base64
# Create a random aesKey encrypt message and store it base64 encoded in AliceReplyEncrypted.base64
aesKey=`openssl rand -hex 32`
openssl enc -e -aes-256-cbc -in AliceReply.plain -out temp/AliceReplyEncrypted.bin -K $aesKey -iv $iv
openssl base64 -A -in temp/AliceReplyEncrypted.bin -out temp/AliceReplyEncrypted.base64
# Now wrap the key by encrypting with Bob's public key with padding mode pkcs1 and store it in AliceEncryptedKey.base64
echo -n "$aesKey"|xxd -r -p>temp/aesKey.bin
openssl pkeyutl -encrypt -in temp/aesKey.bin --out temp/AliceEncryptedKey.bin -pubin -inkey keys/BobPublic.pem -pkeyopt rsa_padding_mode:pkcs1
openssl base64 -A -in temp/AliceEncryptedKey.bin -out temp/AliceEncryptedKey.base64
# Finally sign it with private key using sha256 as digest function and store it in AliceReplySignature
openssl dgst -sha256 -sign keys/AlicePrivate.pem -out temp/AliceReplySignature.bin AliceReply.plain
openssl base64 -A -in temp/AliceReplySignature.bin -out temp/AliceReplySignature.base64
rm temp/*.bin
echo "Message encrypted and signed send .base64 files from temp"


