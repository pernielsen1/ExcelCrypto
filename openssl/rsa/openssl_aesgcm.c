// gcm_encrypt and gcm_decrypt taken from wiki page: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
// the example assumes  EVP_aes_256_gcm
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// unsigned char *tag;
unsigned char *iv;
unsigned char *key;
const EVP_CIPHER *cipher_type;
unsigned int encrypt;

const unsigned long BUFFER_SIZE = 32000;
void handleErrors(const char *strError)
{
    printf("We have errors in %s\n", strError);
}
void dumpBuffer(const char *message, unsigned char *buffer, int bufLen)
{
    int i;
    printf("%s(%d)", message, bufLen);
    for (i=0; i<bufLen; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("encrypt EVP_CIPHER_CTX_new - setting context");

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors("Encrypt EVP_EncryptInit");

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("Encrypt EVP_CIPHER_CTX_ctrl set IV" );

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("Encrypt EVP_EncryptInit_ex");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("Encrypt EVP_EncryptUpdate handle aad");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("Encrypt EVP_EncryptUpdate - do the actual encrypt");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("encrypt EVP_EncryptFinal_ex");
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
        handleErrors("encrypt EVT_CIPHER_CTX_ctrl - get the tag");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag, int tag_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    dumpBuffer("cipherText:", ciphertext, ciphertext_len);
    dumpBuffer("tag:", tag, tag_len);
    dumpBuffer("iv:", iv, iv_len);
    dumpBuffer("aad:", aad, aad_len);
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Decrypt EVP_CIPHER_CTX_new - set context");

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors("decrypt EVP_Decrypt_Init");

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("decrypt EVP_CIPHER_CTX_ctrl - set IV len");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("decrypt EVP_Decrypt_Init set key and iv");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("decrypt EVP_decrypt update handle aad ");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("Decrypt EVP_DecryptUpdate do actual decryption");
    plaintext_len = len;
    dumpBuffer("plain:", plaintext, plaintext_len);
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
        handleErrors("decrypt EVP_cipher_ctx_ctrl - set expected tag");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext, &len);
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int main(int argc, char *argv[]) {
    FILE *f_input, *f_output;
//   unsigned char tempBuffer[BUFFER_SIZE+1000];
    unsigned char *tempBuffer = NULL;
    unsigned char inBuffer[BUFFER_SIZE];
    unsigned char outBuffer[BUFFER_SIZE];
    unsigned char *tag=NULL;
    int aad_len;
    int tag_len;
    int iv_size; 
//    unsigned char aad[TAG_SIZE]; // not used really
    int numBytes;
    int maxBufferSize;
    int result;
    /* Make sure user provides all input  */
    if (argc < 6) {
        printf("Usage: %s /path/to/inputfile /path/to/outputfile key iv enc\n", argv[0]);
    	printf("enc=e means encrypt d=decrypt");
        return -1;
    }
    tag_len = 12;  // assume standard length
    if (argc == 7) {  // tag len passed convert to int using  https://stackoverflow.com/questions/9748393/how-can-i-get-argv-as-int      
        char *p;
        long conv=strtol(argv[6], &p, 10);
        if (errno != 0 || *p != '\0' || conv > INT_MAX || conv < INT_MIN) {
            printf("Error converting tag_len %s", argv[6]);
            exit -1;
        } else {
            tag_len=conv;
        }
    }

    printf("tag_len %d\n", tag_len);
    tag=(unsigned char *) malloc(tag_len);
    long l;    
    key= OPENSSL_hexstr2buf(argv[3], &l);
    iv= OPENSSL_hexstr2buf(argv[4], &l);
    iv_size=(int) l;
    printf("iv_size %d\n", iv_size);
    // default to decrypt
    encrypt = 0;
    maxBufferSize=BUFFER_SIZE+tag_len;
    tempBuffer = (unsigned char*) malloc(maxBufferSize);
    if (strcmp(argv[5], "e") == 0) {
	    encrypt=1;
        maxBufferSize=BUFFER_SIZE;
	    printf("mode encrypt\n");
    }
    cipher_type = EVP_aes_256_gcm();

    /* Open the input file for reading in binary ("rb" mode) */
    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s on input file:%s\n", strerror(errno), argv[1]);
        return errno;
    }

    /* Open and truncate file to zero length  */
    f_output = fopen(argv[2], "wb");
    if (!f_output) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: on output file %s\n", strerror(errno));
        return errno;
    }
    // read input to tempbuffer
    aad_len=0;   // we don't have any aad in this simple example
    numBytes = fread(tempBuffer, sizeof(unsigned char), BUFFER_SIZE + tag_len, f_input);
    if (ferror(f_input)){
        fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
    }
    if (encrypt) {
        memcpy(inBuffer, tempBuffer, numBytes);
    } else {
   	   memcpy(inBuffer, tempBuffer, numBytes - tag_len);
	   memcpy(tag, tempBuffer + numBytes - tag_len, tag_len);
    }
    
    printf("Doing %s infile:%s outfile:%s key:%s iv:%s\n", argv[5], argv[1], argv[2], argv[3], argv[4]);
    if (encrypt) {
        result= gcm_encrypt(inBuffer, numBytes,
                        NULL, 0, 
                        key,
                        iv, iv_size,
                        outBuffer,
                        tag, tag_len);
    }
    else {
        result = gcm_decrypt(inBuffer, numBytes-tag_len,
                            NULL, 0,
                            tag, tag_len,
                            key,
                            iv, iv_size,
                            outBuffer);

    }
    if (result > 0) {
        fwrite(outBuffer, sizeof(unsigned char), result, f_output);
        if (ferror(f_output)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            exit(1);
        }
        if (encrypt) {   // write the tag after the cipher message
            fwrite(tag, sizeof(unsigned char), tag_len, f_output);
            if (ferror(f_output)) {
                fprintf(stderr, "ERROR: fwrite error of TAG: %s\n", strerror(errno));
                exit(1); 
            }
        }
    } 
    /* Encryption done, close the file descriptors */
    free((void *) tag);
    free((void *) tempBuffer);
    fclose(f_input);
    fclose(f_output);
   

    return 0;
}

