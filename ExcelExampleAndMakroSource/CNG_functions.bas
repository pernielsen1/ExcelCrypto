# Attribute VB_Name = "CNG_Functions"
Option Explicit
' https://codekabinett.com/rdumps.php?Lang=2&targetDoc=windows-api-declaration-vba-64-bit
' https://codekabinett.com/download/win32api-data-types-vba.pdf
' https://stackoverflow.com/questions/67294035/basic-encrypting-of-a-text-file
'https://docs.microsoft.com/en-us/windows/win32/medfound/opm-example-code
'#define STATUS_SUCCESS                  ((NTSTATUS)0xvL)
Const BCRYPT_USE_SYSTEM_PREFERRED_RNG As Long = &H2
Const STATUS_SUCCESS As Long = &H0
Const STATUS_NOT_SUPPORTED As Long = &HC00000BB
Const STATUS_INVALID_PARAMETER As Long = &HC000000D
Const BCRYPT_BLOCK_PADDING  As Long = &H1
Const X509_ASN_ENCODING As Long = &H1
Const PKCS_7_ASN_ENCODING As Long = &H10000
Const PKCS_RSA_PRIVATE_KEY As Long = 43
Const PKCS_PRIVATE_KEY_INFO As Long = &H2C ' 44
Const X509_ECC_PRIVATE_KEY As Long = 82
Const RSA_CSP_PUBLICKEYBLOB As Long = 19  ' Hex 13
Const CNG_RSA_PUBLIC_KEY_BLOB As Long = 72
Const CNG_RSA_PRIVATE_KEY_BLOB As Long = 83

Const X509_ASN_ENCODING_XOR_PKCS7 = &H10001

Const CRYPT_STRING_BASE64 As Long = &H1
Const CRYPT_STRING_BASE64HEADER As Long = &H0
Const CRYPT_STRING_HEX As Long = &H4
Const CRYPT_STRING_HEXRAW As Long = &HC
Const X509_PUBLIC_KEY_INFO As Long = &H8
Const CRYPT_ENCODE_ALLOC_FLAG As Long = &H8000
Const NCRYPT_NO_PADDING_FLAG As Long = &H1
Const NCRYPT_PAD_PKCS1_FLAG As Long = &H2&
Const NCRYPT_PAD_OAEP_FLAG As Long = &H4
Const BCRYPT_ECDH_P256_ALGORITHM As String = "ECDH_P256"
Const BCRYPT_ECCPRIVATE_BLOB As String = "ECCPRIVATEBLOB" & vbNullChar
Const BCRYPT_ECCPUBLIC_BLOB As String = "ECCPUBLICBLOB" & vbNullChar
Const BCRYPT_RSAPUBLIC_BLOB As String = "RSAPUBLICBLOB" & vbNullChar
Const BCRYPT_RSAPRIVATE_BLOB As String = "RSAPRIVATEBLOB" & vbNullChar
Const BCRYPT_RSAFULLPRIVATE_BLOB As String = "RSAFULLPRIVATEBLOB" & vbNullChar
Const LEGACY_RSAPUBLIC_BLOB As String = "CAPIPUBLICBLOB" & vbNullChar
Const LEGACY_RSAPRIVATE_BLOB As String = "CAPIPRIVATEBLOB" & vbNullChar
Const BCRYPT_AUTH_TAG_LENGTH As String = "AuthTagLength" & vbNullChar
Const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION As Long = 1

Const BCRYPT_RSAPUBLIC_MAGIC = &H31415352
Const BCRYPT_RSAPRIVATE_MAGIC = &H32415352

Const BCRYPT_ECDH_PUBLIC_P256_MAGIC = &H314B4345
Const BCRYPT_ECDH_PRIVATE_P256_MAGIC = &H324B4345
Const BCRYPT_KDF_RAW_SECRET As String = "TRUNCATE" & vbNullChar
Const BCRYPT_SHA256_ALGORITHM As String = "SHA256" & vbNullChar
Const BCRYPT_RSA_ALGORITHM As String = "RSA" & vbNullChar
Const BCRYPT_RSA_SIGN_ALGORITHM As String = "RSA_SIGN" & vbNullChar

Const BCRYPT_PAD_NONE As Long = &H1
Const BCRYPT_PAD_PKCS1 As Long = &H2
Const BCRYPT_PAD_OAEP As Long = &H4
Const MyNULL As LongPtr = 0&
Const BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = &H1
Const BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG = &H2



Private Type CRYPT_OBJID_BLOB
   cbData As Long
   pbData As LongPtr
End Type

Private Type CRYPT_BIT_BLOB
   cbData As Long
   pbData As LongPtr
End Type

' authTag(authTagLengths.dwMinLength
Private Type BCRYPT_AUTH_TAG_LENGTHS_STRUCT
  dwMinLength As Long
  dwMaxLength As Long
  dwIncrement As Long
End Type

' typedef struct _BCRYPT_PKCS1_PADDING_INFO {
'  LPCWSTR pszAlgId;
' } BCRYPT_PKCS1_PADDING_INFO;

Private Type BCRYPT_PKCS1_PADDING_INFO
    algId As String
End Type
Private Type BCRYPT_OAEP_PADDING_INFO
    algId As String
    pbLabel As LongPtr
    cbLabel As Long
End Type
Private Type CRYPT_ALGORITHM_IDENTIFIER
   pszObjId As LongPtr
   Parameters As CRYPT_OBJID_BLOB
End Type
Private Type CERT_PUBLIC_KEY_INFO_SHORT
    algorithm As CRYPT_ALGORITHM_IDENTIFIER
    publicKey As CRYPT_BIT_BLOB
End Type
Private Type CERT_PUBLIC_KEY_INFO
    algorithm As CRYPT_ALGORITHM_IDENTIFIER
    publicKey As CRYPT_BIT_BLOB
    buffer(1 To 4096) As Byte
End Type
Private Type RSA_PUBLIC_KEY
    btype As Byte
    bVersion As Byte
    reserved As Integer
    alg_id As Long
    Magic As Long
    bitlen As Long
    pubExp As Long
    modulus(1 To 4096)  As Byte
End Type
Private Type CRYPT_DER_BLOB
    cbData As Long
    pbData As LongPtr
End Type
Private Type CRYPT_PRIVATE_KEY_INFO
    version As Long
    algorithm As CRYPT_ALGORITHM_IDENTIFIER
    privateKey As CRYPT_DER_BLOB
    pAttributes As LongPtr
End Type
Private Type BCRYPT_RSAKEY_BLOB
  Magic As Long
  BitLength As Long
  cbPublicExp As Long
  cbModulus As Long
  cbPrime1 As Long
  cbPrime2 As Long
End Type
Private Type CNG_RSA_PUBLIC_BLOB
    blob As BCRYPT_RSAKEY_BLOB
    pubExp(1 To 3) As Byte
    modulus(1 To 1024) As Byte
End Type
Private Type CRYPT_ECC_PRIVATE_KEY_INFO
    version As Long
    privateKey As CRYPT_DER_BLOB
    pszCurveOid As LongPtr
    publicKey As CRYPT_DER_BLOB
End Type
Private Type BCRYPT_ECCKEY_BLOB
    dwMagic As Long
    cbKey As Long
End Type
Private Type BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    cbSize As Long
    dwInfoVersion As Long
    pbNonce As LongPtr
    cbNonce As Long
    pbAuthData As LongPtr
    cbAuthData As Long
    pbTag As LongPtr
    cbTag As Long
    pbMacContext As LongPtr
    cbMacContext As Long
    cbAAD As Long
    cbData As LongLong
    dwFlags As Long
End Type


'#SECTION Prototypes - for calling windows functions
' Kernel32.dll
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal toPtr As LongPtr, ByVal fromPtr As LongPtr, ByVal Length As LongPtr)
Private Declare PtrSafe Sub ZeroMemory Lib "kernel32.dll" Alias "RtlZeroMemory" (Destination As Any, ByVal Length As Long)
' Bcrypt.dll
Private Declare PtrSafe Function BCryptOpenAlgorithmProvider Lib "bcrypt.dll" (ByRef phalgorithm As LongPtr, ByVal pszAlgId As LongPtr, ByVal pszImplementation As LongPtr, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptCloseAlgorithmProvider Lib "bcrypt.dll" (ByVal hAlgorithm As LongPtr, ByVal dwFlags As Long)

Private Declare PtrSafe Function BCryptDestroyKey Lib "bcrypt.dll" (ByVal hKey As LongPtr) As Long
Private Declare PtrSafe Function BCryptDestroyHash Lib "bcrypt.dll" (ByVal hHash As LongPtr) As Long
Private Declare PtrSafe Function BCryptDestroySecret Lib "bcrypt.dll" (ByVal hSecret As LongPtr) As Long
Private Declare PtrSafe Function BCryptGenRandom Lib "bcrypt.dll" (ByVal hAlgHandle As LongPtr, ByVal pbBuffer As LongPtr, ByVal cbBuffer As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptGetProperty Lib "bcrypt.dll" (ByVal hObject As LongPtr, ByVal pszProperty As LongPtr, ByVal pbOutput As LongPtr, ByVal cbOutput As Long, ByRef pcbResult As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptSetProperty Lib "bcrypt.dll" (ByVal hObject As LongPtr, ByVal pszProperty As LongPtr, ByRef pbInput As Any, ByVal cbInput As Long, ByVal dfFlags As Long) As Long
Private Declare PtrSafe Function BCryptGenerateSymmetricKey Lib "bcrypt.dll" (ByVal hAlgorithm As LongPtr, ByRef hKey As LongPtr, pbKeyObject As Any, ByVal cbKeyObject As Long, pbSecret As Any, ByVal cbSecret As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptEncrypt Lib "bcrypt.dll" (ByVal hKey As LongPtr, ByVal pbInput As LongPtr, ByVal cbInput As Long, ByVal pPaddingInfo As LongPtr, ByVal pbIV As LongPtr, ByVal cbIV As Long, ByVal pbOutput As LongPtr, ByVal cbOutput As Long, ByRef pcbResult As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptDecrypt Lib "bcrypt.dll" (ByVal hKey As LongPtr, ByVal pbInput As LongPtr, ByVal cbInput As Long, ByVal pPaddingInfo As LongPtr, ByVal pbIV As LongPtr, ByVal cbIV As Long, ByVal pbOutput As LongPtr, ByVal cbOutput As Long, ByRef pcbResult As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptImportKeyPair Lib "bcrypt.dll" (ByVal hAlgoritm As LongPtr, ByVal hImportKey As LongPtr, ByVal pszBlobType As LongPtr, ByRef pbKeyObject As LongPtr, ByVal pbInput As LongPtr, ByVal cbInput As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptSecretAgreement Lib "bcrypt.dll" (ByVal hPrivateKey As LongPtr, ByVal hPublicKey As LongPtr, ByRef hSecretHandle As LongPtr, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptDeriveKey Lib "bcrypt.dll" (ByVal hSharedSecret As LongPtr, ByVal pwszKDF As LongPtr, ByVal pParameterList As LongPtr, ByVal pDerivedKey As LongPtr, ByVal cbDerivedKey As Long, ByRef cbNumBytes As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptCreateHash Lib "bcrypt.dll" (ByVal hAlgorithm As LongPtr, ByRef hHash As LongPtr, ByVal pbHashObject As LongPtr, ByVal cbHashObject As Long, ByVal pbSecret As LongPtr, ByVal cbSecret As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptHashData Lib "bcrypt.dll" (ByVal hHash As LongPtr, ByVal pbData As LongPtr, ByVal cbData As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptFinishHash Lib "bcrypt.dll" (ByVal hHash As LongPtr, ByVal pbData As LongPtr, ByVal cbData As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptExportKey Lib "bcrypt.dll" (ByVal hKey As LongPtr, ByVal hExportKey As LongPtr, ByVal pszBlobType As LongPtr, ByVal pbOutput As LongPtr, ByVal cbOutput As Long, ByRef cbResult As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptSignHash Lib "bcrypt.dll" (ByVal hKey As LongPtr, ByVal pPaddingInfo As LongPtr, ByVal pbInput As LongPtr, ByVal cbInput As Long, ByVal pbOutput As LongPtr, ByVal cbOutput As Long, ByRef pcbResult As Long, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function BCryptVerifySignature Lib "bcrypt.dll" (ByVal hKey As LongPtr, ByVal pPaddingInfo As LongPtr, ByVal pbHash As LongPtr, ByVal cbHash As Long, ByVal pbSignature As LongPtr, ByVal cbSignature As Long, ByVal dwFlags As Long) As Long
' Crypt32.dll
Private Declare PtrSafe Function CryptBinaryToString Lib "crypt32.dll" Alias "CryptBinaryToStringW" (ByRef pbBinary As Byte, ByVal cbBinary As Long, ByVal dwFlags As Long, ByVal pszString As LongPtr, ByRef pcchString As Long) As Long
Private Declare PtrSafe Function CryptStringToBinary Lib "crypt32.dll" Alias "CryptStringToBinaryW" (ByVal pszString As LongPtr, ByVal cchString As Long, ByVal dwFlags As Long, ByVal pbBinary As LongPtr, ByRef pcbBinary As Long, ByRef pdwSkip As Long, ByRef pdwFlags As Long) As Long
Private Declare PtrSafe Function CertCreateCertificateContext Lib "crypt32.dll" (ByVal dwCertEncodingType As Long, ByVal pbCertEncoded As LongPtr, ByVal cbCertEncoded As Long) As LongPtr
Private Declare PtrSafe Function CryptDecodeObjectEx Lib "crypt32.dll" (ByVal wCertEncodingType As Long, ByVal lpszStructType As Long, ByVal pbEncoded As LongPtr, ByVal cbEncoded As Long, ByVal dwFlags As Long, ByRef pDecodePara As LongPtr, ByVal pvStructInfo As LongPtr, ByRef pcbStructInfo As Long) As Long
Private Declare PtrSafe Function CryptEncodeObjectEx Lib "crypt32.dll" (ByVal dwCertEncodingType As Long, ByVal lpszStructType As Long, ByVal pvStructInfo As LongPtr, ByVal dwFlags As Long, ByRef pEncodePara As LongPtr, ByVal pbEncoded As LongPtr, ByRef cbEncoded As Long) As Long
            
            
            

'   See github.com/Azure/azure-c-shared-utility/blob/… for a complete example of how to import keys from
' https://stackoverflow.com/questions/58419870/how-to-use-bcrypt-for-rsa-asymmetric-encryption

'---------------------------------------------------------------
'#RSA_SECTION
'----------------------------------------------------------------------------------------------------------------------
' RSA Section.
' RSA_Encrypt - encrypt hex string given public key passed in PEM and padding scheme - for OAEP pass init string also
' RSA_Decrypt - decrypt hex string given public key passed in PEM and padding scheme - for OAEP pass init string also
' RSA_SignHash - Signs has with private RSA key
' RSA_VerifySignature - Verifies that signature is OK for a hash using the public key
' RSA_CreatePrivatePEM - Create a private key PEM from Modulus, exponent, prime1, prime2
' RSA_CreatePublicPEM - Create a public key PEM from modulus and exponent
' RSA_getParameter - extract a parameter from a PEM
' Internal functions
' RSA_LoadPrivateKey
' RSA_LoadPublicKey
'-----------------------------------------------------------------------------------------------------------------------
Public Function RSA_Encrypt(ByVal pem As String, ByVal plain As String, Optional ByVal strPadding As String = "PKCS1", Optional ByVal hashAlgorithm As String = "SHA256", Optional ByVal strPaddingString As String = "010203") As String
    Dim hAlgHandle As LongPtr, hKey As LongPtr, plainByte() As Byte, dwFlags As Long, strRes As String
    Dim BCryptOAEPPaddingInfo As BCRYPT_OAEP_PADDING_INFO, paddingBytes() As Byte, pPadding As LongPtr
    
    hAlgHandle = MyNULL
    hKey = MyNULL
    
    strRes = decode(CRYPT_STRING_HEXRAW, plain, plainByte)
    If (strRes <> "") Then
        strRes = "RSA_Encrypt Error in plain hex input : " & strRes
        GoTo Exit_EncryptRSAPEMNew
    End If
    
    strRes = MyBCryptGetPaddingFlags(strPadding, dwFlags)
    If (strRes <> "") Then
        strRes = "Error in getting padding in RSA_Encrypt : " & strRes
        GoTo Exit_EncryptRSAPEMNew
    End If
    
    pPadding = MyNULL
    If (strPadding = "OAEP") Then
        hashAlgorithm = hashAlgorithm & vbNullChar
        strRes = MyBCryptSetBCryptOAEPPaddingInfo(BCryptOAEPPaddingInfo, hashAlgorithm, strPaddingString, paddingBytes)
        If (strRes <> "") Then
            strRes = "Error in OAEP  padding in RSA_Encrypt : " & strRes
            GoTo Exit_EncryptRSAPEMNew
        End If
        pPadding = VarPtr(BCryptOAEPPaddingInfo)
    End If
    strRes = RSA_LoadPublicKey(pem, BCRYPT_RSA_ALGORITHM, hAlgHandle, hKey)
    If (strRes <> "") Then
        GoTo Exit_EncryptRSAPEMNew
    End If

    strRes = MyBCryptEncryptDecrypt("ENCRYPT", plainByte, hKey, dwFlags, MyNULL, 0, pPadding)
Exit_EncryptRSAPEMNew:
     RSA_Encrypt = strRes
     cleanUpAlgorithmAndKey hAlgHandle, hKey
End Function
Public Function RSA_Decrypt(ByVal pem As String, ByVal cipher As String, Optional ByVal strPadding As String = "PKCS1", Optional ByVal hashAlgorithm As String = "SHA256", Optional ByVal strPaddingString As String = "010203") As String

    Dim strRes As String, hAlgHandle As LongPtr, hKey As LongPtr, cipherByte() As Byte, dwFlags As Long
    Dim BCryptOAEPPaddingInfo As BCRYPT_OAEP_PADDING_INFO, paddingBytes() As Byte, pPadding As LongPtr
    
    hAlgHandle = MyNULL
    hKey = MyNULL
    strRes = decode(CRYPT_STRING_HEXRAW, cipher, cipherByte)
    If (strRes <> "") Then
        strRes = "Error in cipher hex input : " & strRes
        GoTo Exit_DecryptRSA
    End If
    strRes = MyBCryptGetPaddingFlags(strPadding, dwFlags)
    If (strRes <> "") Then
        strRes = "Error in getting padding in RSA_Decrypt : " & strRes
        GoTo Exit_DecryptRSA
    End If
    pPadding = MyNULL
    If (strPadding = "OAEP") Then
        hashAlgorithm = hashAlgorithm & vbNullChar
        strRes = MyBCryptSetBCryptOAEPPaddingInfo(BCryptOAEPPaddingInfo, hashAlgorithm, strPaddingString, paddingBytes)
        If (strRes <> "") Then
            strRes = "Error in OAEP  padding in RSA_Encrypt : " & strRes
            GoTo Exit_DecryptRSA
        End If
        pPadding = VarPtr(BCryptOAEPPaddingInfo)
    End If
    
    strRes = RSA_LoadPrivateKey(pem, BCRYPT_RSA_ALGORITHM, hAlgHandle, hKey)
    If (strRes <> "") Then
        GoTo Exit_DecryptRSA
    End If
    
    strRes = MyBCryptEncryptDecrypt("DECRYPT", cipherByte, hKey, dwFlags, MyNULL, 0, pPadding)
Exit_DecryptRSA:
     RSA_Decrypt = strRes
     cleanUpAlgorithmAndKey hAlgHandle, hKey
End Function

Public Function RSA_VerifySignature(ByVal pem As String, ByVal strHash As String, ByVal strSignature As String, ByVal algorithm As String, ByVal strOK As String) As String
    Dim hAlg As LongPtr, hKey As LongPtr, strRes As String, hash() As Byte, signature() As Byte, dwRes As Long, dwFlags As Long, paddingInfo As BCRYPT_PKCS1_PADDING_INFO
    strRes = decode(CRYPT_STRING_HEXRAW, strHash, hash)
    If (strRes <> "") Then
        GoTo Exit_RSA_VerifySignature
    End If
    strRes = decode(CRYPT_STRING_HEXRAW, strSignature, signature)
    If (strRes <> "") Then
        GoTo Exit_RSA_VerifySignature
    End If
    strRes = RSA_LoadPublicKey(pem, BCRYPT_RSA_SIGN_ALGORITHM, hAlg, hKey)
    If (strRes <> "") Then
        GoTo Exit_RSA_VerifySignature
    End If
    paddingInfo.algId = algorithm & vbNullChar
    dwFlags = BCRYPT_PAD_PKCS1

    dwRes = BCryptVerifySignature(hKey, VarPtr(paddingInfo), VarPtr(hash(1)), UBound(hash), VarPtr(signature(1)), UBound(signature), dwFlags)
    If (dwRes <> 0) Then
        strRes = "Error verifying signature BCryptVerifySignature" & Hex(dwRes)
    Else
        strRes = strOK
    End If
    
Exit_RSA_VerifySignature:
    RSA_VerifySignature = strRes
End Function
Public Function RSA_SignHash(ByVal pem As String, ByVal strDataToSign As String, ByVal signingAlgorithm As String) As String
' https://stackoverflow.com/questions/67600792/rsa-sha512-signature-generated-by-windows-cngcryptography-next-generation-ncr
    Dim hAlg As LongPtr, hKey As LongPtr, strRes As String, dwFlags As Long, dwRes As Long, dwResult As Long
    Dim dataToSign() As Byte, signature() As Byte, paddingInfo As BCRYPT_PKCS1_PADDING_INFO
    
    strRes = decode(CRYPT_STRING_HEXRAW, strDataToSign, dataToSign)
    If (strRes <> "") Then
        GoTo Exit_RSA_SignHash
    End If
    strRes = RSA_LoadPrivateKey(pem, BCRYPT_RSA_SIGN_ALGORITHM, hAlg, hKey)
    If (strRes <> "") Then
        GoTo Exit_RSA_SignHash
    End If
    paddingInfo.algId = signingAlgorithm & vbNullChar
    dwFlags = BCRYPT_PAD_PKCS1
    dwRes = BCryptSignHash(hKey, VarPtr(paddingInfo), VarPtr(dataToSign(1)), UBound(dataToSign), MyNULL, 0, dwResult, dwFlags)
    If (dwRes <> 0) Then
        strRes = "Error retrieving size for BCryptSignHash:" & Hex(dwRes)
        GoTo Exit_RSA_SignHash
    End If
    ReDim signature(1 To dwResult)
    dwRes = BCryptSignHash(hKey, VarPtr(paddingInfo), VarPtr(dataToSign(1)), UBound(dataToSign), VarPtr(signature(1)), UBound(signature), dwResult, dwFlags)
    If (dwRes <> 0) Then
        strRes = "Error performing the signing in BCryptSignHash:" & Hex(dwRes)
        GoTo Exit_RSA_SignHash
    End If
    strRes = encode(CRYPT_STRING_HEXRAW, signature)
Exit_RSA_SignHash:
    RSA_SignHash = strRes
End Function
Public Function RSA_getParameter(ByVal pem As String, ByVal parm As String) As String
    Dim hAlgHandle As LongPtr, hKey As LongPtr, strRes As String
    Dim BCryptRsaKeyBlob As BCRYPT_RSAKEY_BLOB
    Dim keyBlob() As Byte
    Dim keyType As String
    hKey = MyNULL
    hAlgHandle = MyNULL
    ' If this is private we can get it all
    keyType = BCRYPT_RSAFULLPRIVATE_BLOB
    strRes = RSA_LoadPrivateKey(pem, BCRYPT_RSA_ALGORITHM, hAlgHandle, hKey)
    If (strRes <> "") Then
        ' naah didn't work let us see if it is a public
        keyType = BCRYPT_RSAPUBLIC_BLOB
        strRes = RSA_LoadPublicKey(pem, BCRYPT_RSA_ALGORITHM, hAlgHandle, hKey)
    End If
    If (strRes <> "") Then
        GoTo Exit_RSA_getParameter
    End If
    ' Now we have imported the key - let's find out what it is and export it
    strRes = MyBCryptExportKey(hKey, keyType, keyBlob)
    If (strRes <> "") Then
        GoTo Exit_RSA_getParameter
    End If
    parm = UCase(parm)
    CopyMemory VarPtr(BCryptRsaKeyBlob), VarPtr(keyBlob(1)), LenB(BCryptRsaKeyBlob)
    If (parm = "EXPONENT") Then  'Exponent in both public and private blob
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob), BCryptRsaKeyBlob.cbPublicExp)
    End If
    If (parm = "MODULUS") Then 'Modulus in both public and private blob
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp, BCryptRsaKeyBlob.cbModulus)
    End If
    If (parm = "PRIME1" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus, _
                BCryptRsaKeyBlob.cbPrime1)
    End If
    If (parm = "PRIME2" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
        + BCryptRsaKeyBlob.cbPrime1, BCryptRsaKeyBlob.cbPrime2)
    End If
    If (parm = "EXPONENT1" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
        + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime2, BCryptRsaKeyBlob.cbPrime1)
    End If
    If (parm = "EXPONENT2" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
        + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime2 + BCryptRsaKeyBlob.cbPrime1, BCryptRsaKeyBlob.cbPrime1)
    End If
    If (parm = "COEFFICIENT" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
        + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime2 + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1, BCryptRsaKeyBlob.cbPrime1)
    End If
    If (parm = "PRIVATEEXPONENT" And keyType = BCRYPT_RSAFULLPRIVATE_BLOB) Then
        strRes = extractBytesToHexStr(keyBlob, 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
        + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime2 + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1, _
        BCryptRsaKeyBlob.cbModulus)
    End If
    ' Still here with blank strRes means invalid parameter
    If (strRes = "") Then
        strRes = "Invalid parameter for public keys possible values are Exponent and Modulus, for private it is Exponent, Modulus, Prime1, Prime2, Exponent1, Exponent2, Coefficient, PrivateExponent"
    End If
Exit_RSA_getParameter:
    RSA_getParameter = strRes
    cleanUpAlgorithmAndKey hAlgHandle, hKey
End Function
Public Function RSA_createPrivatePEM(ByVal modulus As String, ByVal exponent As String, ByVal prime1 As String, ByVal prime2 As String) As String
    Dim BCryptRsaKeyBlob As BCRYPT_RSAKEY_BLOB
    Dim keyBlob() As Byte, dwRes As Long, hAlgHandle As LongPtr, hKey As LongPtr, strRes As String, ExponentByte() As Byte, ModulusByte() As Byte, Prime1Byte() As Byte, Prime2Byte() As Byte
    ' Setup a BCRYPT_RSAKEY_BLOB for a prive key, get algoritm handle and import to hKey
    hAlgHandle = MyNULL
    hKey = MyNULL
    
    exponent = ASN_removeLeadingZero(exponent)  ' a 00 may be in front to make a big int "positive" - remove it here
    modulus = ASN_removeLeadingZero(modulus) ' a 00 may be in front to make a big int "positive" - remove it here
    prime1 = ASN_removeLeadingZero(prime1) ' a 00 may be in front to make a big int "positive" - remove it here
    prime2 = ASN_removeLeadingZero(prime2) ' a 00 may be in front to make a big int "positive" - remove it here
    
    BCryptRsaKeyBlob.Magic = BCRYPT_RSAPRIVATE_MAGIC
    BCryptRsaKeyBlob.cbPublicExp = Len(exponent) / 2
    BCryptRsaKeyBlob.cbModulus = Len(modulus) / 2
    BCryptRsaKeyBlob.BitLength = BCryptRsaKeyBlob.cbModulus * 8
    BCryptRsaKeyBlob.cbPrime1 = Len(prime1) / 2
    BCryptRsaKeyBlob.cbPrime2 = Len(prime1) / 2
    ' Get Alg handle and create the keyblob
    dwRes = BCryptOpenAlgorithmProvider(hAlgHandle, StrPtr(BCRYPT_RSA_ALGORITHM), 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error getting AlgoritmProvider for:" & BCRYPT_RSA_ALGORITHM
        GoTo Exit_CreateRSAPrivatePEM
    End If
    ' The minus 1 is since we    remove the first byte in public key which is 04
    appendToByteArray keyBlob, VarPtr(BCryptRsaKeyBlob), LenB(BCryptRsaKeyBlob)
    appendHexStrToByteArray keyBlob, exponent
    appendHexStrToByteArray keyBlob, modulus
    appendHexStrToByteArray keyBlob, prime1
    appendHexStrToByteArray keyBlob, prime2
    dwRes = BCryptImportKeyPair(hAlgHandle, 0, StrPtr(BCRYPT_RSAPRIVATE_BLOB), hKey, VarPtr(keyBlob(1)), UBound(keyBlob), 0)
    If (dwRes <> 0) Then
        strRes = "Error in importing key:" & Hex(dwRes)
        GoTo Exit_CreateRSAPrivatePEM
    End If
    Dim keyBlobFull() As Byte
    strRes = MyBCryptExportKey(hKey, BCRYPT_RSAFULLPRIVATE_BLOB, keyBlobFull)
    If (strRes <> "") Then
        GoTo Exit_CreateRSAPrivatePEM
    End If
    
    Dim exponent1 As String, exponent2 As String, coefficient As String, privateexponent As String
    Dim startIndex As Long
    
    startIndex = 1 + LenB(BCryptRsaKeyBlob) + BCryptRsaKeyBlob.cbPublicExp + BCryptRsaKeyBlob.cbModulus _
                       + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime2
    exponent1 = extractBytesToHexStr(keyBlobFull, startIndex, BCryptRsaKeyBlob.cbPrime1)
    exponent2 = extractBytesToHexStr(keyBlobFull, startIndex + BCryptRsaKeyBlob.cbPrime1, BCryptRsaKeyBlob.cbPrime1)
    coefficient = extractBytesToHexStr(keyBlobFull, startIndex + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1, _
                    BCryptRsaKeyBlob.cbPrime1)
    privateexponent = extractBytesToHexStr(keyBlobFull, startIndex + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1 + BCryptRsaKeyBlob.cbPrime1, _
                    BCryptRsaKeyBlob.cbModulus)
    modulus = ASN_addLeadingZero(modulus)
    exponent = ASN_addLeadingZero(exponent)
    prime1 = ASN_addLeadingZero(prime1)
    prime2 = ASN_addLeadingZero(prime2)
    
    exponent1 = ASN_addLeadingZero(exponent1)
    exponent2 = ASN_addLeadingZero(exponent2)
    coefficient = ASN_addLeadingZero(coefficient)
    privateexponent = ASN_addLeadingZero(privateexponent)
    
    Dim tag2 As String, tag6 As String, tag5 As String, keyBytes As String, tag6and5 As String, tag4 As String, full As String
    tag2 = ASN_getTag("02", "00")
    tag6 = ASN_getTag("06", ASN_getOID("RSA"))
    tag5 = ASN_getTag("05", "")
    tag6and5 = ASN_getTag("30", tag6 & tag5)
    keyBytes = ASN_getTag("30", tag2 & ASN_getTag("02", modulus) & ASN_getTag("02", exponent) & _
               ASN_getTag("02", privateexponent) & _
               ASN_getTag("02", prime1) & ASN_getTag("02", prime2) & _
               ASN_getTag("02", exponent1) & ASN_getTag("02", exponent2) & ASN_getTag("02", coefficient))
    tag4 = ASN_getTag("04", keyBytes)
    full = ASN_getTag("30", tag2 & tag6and5 & tag4)
                      
    strRes = "-----BEGIN PRIVATE KEY-----" & _
                            Util_HexStrToBase64(full) & _
                          "-----END PRIVATE KEY-----"
Exit_CreateRSAPrivatePEM:
    RSA_createPrivatePEM = strRes
    cleanUpAlgorithmAndKey hAlgHandle, hKey
End Function
Public Function RSA_CreatePublicPEM(ByVal modulus As String, ByVal exponent As String) As String
' https://stackoverflow.com/questions/18995687/converting-rsa-keys-into-subjectpublickeyinfo-form-from-bigintegers
    Dim oidStr As String, strModulus As String, strExponent As String, strBitString As String, strKey As String, tag06_OID As String, tag05_OIDUnusedBits As String, full As String, keyBitLen As Integer
    ' Sometimes we get a 00 in front sometimes not - remove if it is there
    If (Len(modulus) Mod 16 <> 0) Then
        modulus = Mid(modulus, 3, Len(modulus) - 2)
    End If
    ' TBD comments what is the name of this identifier we build here
    keyBitLen = (Len(modulus) / 2) * 8  'Div by 2 to go from hex str to bytes
    tag06_OID = ASN_getTag("06", ASN_getOID("RSA"))
    tag05_OIDUnusedBits = "0500"  ' No unused bits
    oidStr = ASN_getTag("30", tag06_OID & tag05_OIDUnusedBits)
    
    strModulus = ASN_getTag("02", "00" & modulus)  ' In this form the 00 in front is needed
    strExponent = ASN_getTag("02", exponent)
    strKey = ASN_getTag("30", strModulus & strExponent)
    strBitString = ASN_getTag("03", "00" & strKey) ' The 00 in front is for "no unused bits"
   
    full = ASN_getTag("30", oidStr & strBitString)
        RSA_CreatePublicPEM = "-----BEGIN PUBLIC KEY-----" & _
        Util_HexStrToBase64(full) & _
        "-----END PUBLIC KEY-----"
End Function
Private Function RSA_LoadPrivateKey(ByVal strKey As String, ByVal algorithm As String, ByVal hAlgHandle As LongPtr, ByRef hKey As LongPtr) As String
    Dim keyBlob() As Byte, keyInfo() As Byte, KeyASN() As Byte, rsaKeyBlob() As Byte
    Dim strRes As String, dwRes As Long
    Dim PrivateKeyInfoStruct As CRYPT_PRIVATE_KEY_INFO
    ' get Provider
    dwRes = BCryptOpenAlgorithmProvider(hAlgHandle, StrPtr(algorithm), 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error getting AlgoritmProvider for:" & BCRYPT_RSA_ALGORITHM
        GoTo Exit_RSA_LoadPrivateKey
    End If
    ' Decode the PEM to privateKeyInfoStruct
    strRes = PemToKeyInfo(strKey, X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, keyInfo, VarPtr(PrivateKeyInfoStruct), LenB(PrivateKeyInfoStruct))
    If (strRes <> "") Then
        GoTo Exit_RSA_LoadPrivateKey
    End If
    ' Decode the PrivateKey to LEGACY Format
    appendToByteArray KeyASN, PrivateKeyInfoStruct.privateKey.pbData, PrivateKeyInfoStruct.privateKey.cbData
    strRes = MyCryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, KeyASN, rsaKeyBlob)
    If (strRes <> "") Then
        GoTo Exit_RSA_LoadPrivateKey
    End If
    ' Import the Private key
    dwRes = BCryptImportKeyPair(hAlgHandle, MyNULL, StrPtr(LEGACY_RSAPRIVATE_BLOB), hKey, VarPtr(rsaKeyBlob(1)), UBound(rsaKeyBlob), 0)
    If (dwRes <> 0) Then
          strRes = "Error importing keypair or:" & BCRYPT_RSA_ALGORITHM
        GoTo Exit_RSA_LoadPrivateKey
    End If
    RSA_LoadPrivateKey = ""
    Exit Function
Exit_RSA_LoadPrivateKey:
     RSA_LoadPrivateKey = strRes ' Cleanup hAlg and hKey handled in calling function
End Function
Private Function RSA_LoadPublicKey(ByVal strKey As String, ByVal algorithm As String, ByVal hAlgHandle As LongPtr, ByRef hKey As LongPtr) As String
    Dim keyBlob() As Byte, keyInfo() As Byte, strRes As String, dwRes As Long, rsaPubLicKey() As Byte, publicKeyASN() As Byte
    Dim BCryptRsaKeyBlob As BCRYPT_RSAKEY_BLOB
    Dim keyInfoStruct As CERT_PUBLIC_KEY_INFO_SHORT
    Dim PrivateKeyInfoStruct As CRYPT_PRIVATE_KEY_INFO
    ' Decode the PEM to DER and pack it up to a KeyInfo
    strRes = PemToKeyInfo(strKey, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, keyInfo, VarPtr(keyInfoStruct), LenB(keyInfoStruct))
    If (strRes <> "") Then
        GoTo Exit_RSA_LoadPublicKey
    End If
    
    appendToByteArray publicKeyASN, keyInfoStruct.publicKey.pbData, keyInfoStruct.publicKey.cbData
    strRes = MyCryptDecodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, publicKeyASN, rsaPubLicKey)
    Dim myRSA_Public_KEY As RSA_PUBLIC_KEY
    If (UBound(rsaPubLicKey) > LenB(myRSA_Public_KEY)) Then
        strRes = "the rsapublic key is to big"
        GoTo Exit_RSA_LoadPublicKey
    End If
    CopyMemory VarPtr(myRSA_Public_KEY), VarPtr(rsaPubLicKey(1)), UBound(rsaPubLicKey)
    Dim modulus() As Byte
    appendToByteArray modulus, VarPtr(myRSA_Public_KEY.modulus(1)), myRSA_Public_KEY.bitlen / 8
    reverseEndian modulus ' and we reverse the byte order
    strRes = encode(CRYPT_STRING_HEXRAW, modulus)
    BCryptRsaKeyBlob.Magic = BCRYPT_RSAPUBLIC_MAGIC
    BCryptRsaKeyBlob.cbPublicExp = 3
    BCryptRsaKeyBlob.cbModulus = myRSA_Public_KEY.bitlen / 8
    BCryptRsaKeyBlob.BitLength = myRSA_Public_KEY.bitlen
    BCryptRsaKeyBlob.cbPrime1 = 0
    BCryptRsaKeyBlob.cbPrime2 = 0
    ' so get an Algorithm provider
    dwRes = BCryptOpenAlgorithmProvider(hAlgHandle, StrPtr(algorithm), 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error getting AlgoritmProvider for:" & algorithm
        GoTo Exit_RSA_LoadPublicKey
    End If
    ' The minus 1 is since we    remove the first byte in public key which is 04
    appendToByteArray keyBlob, VarPtr(BCryptRsaKeyBlob), LenB(BCryptRsaKeyBlob)
    appendToByteArray keyBlob, VarPtr(myRSA_Public_KEY.pubExp), BCryptRsaKeyBlob.cbPublicExp  'i.e. 3
    appendToByteArray keyBlob, VarPtr(modulus(1)), BCryptRsaKeyBlob.cbModulus
    
    dwRes = BCryptImportKeyPair(hAlgHandle, 0, StrPtr(BCRYPT_RSAPUBLIC_BLOB), hKey, VarPtr(keyBlob(1)), UBound(keyBlob), 0)
    If (dwRes <> 0) Then
        strRes = "Error im bcryptimportkey" & Hex(dwRes)
        GoTo Exit_RSA_LoadPublicKey
    End If
    RSA_LoadPublicKey = ""
    Exit Function
Exit_RSA_LoadPublicKey:
        RSA_LoadPublicKey = strRes      ' cleanup is handled in calling function
End Function
'---------------------------------------------------------------------------------------------
' #MyBCrypt -functions = wrap BCrypt functions
'
'--------------
Private Function MyBCryptEncryptDecrypt(ByVal strFunc As String, ByRef inputBuffer() As Byte, ByVal hKey As LongPtr, ByVal dwPadding As Long, Optional pIV As LongPtr = MyNULL, Optional cbIV = 0, Optional ByVal pPaddingInfo As LongPtr = MyNULL) As String
    Dim dwResult As Long, dwRes As Long, resultBuffer() As Byte
    If (strFunc = "DECRYPT") Then
        dwRes = BCryptDecrypt(hKey, VarPtr(inputBuffer(1)), UBound(inputBuffer), pPaddingInfo, pIV, cbIV, MyNULL, 0, dwResult, dwPadding)
        If (dwRes <> 0) Then
            MyBCryptEncryptDecrypt = "Error in BCryptDecrypt Error code:" & Hex(dwRes)
            Exit Function
        End If
    Else
        dwRes = BCryptEncrypt(hKey, VarPtr(inputBuffer(1)), UBound(inputBuffer), pPaddingInfo, pIV, cbIV, MyNULL, 0, dwResult, dwPadding)
        If (dwRes <> 0) Then
            MyBCryptEncryptDecrypt = "Error in BCryptEncrypt Error code:" & Hex(dwRes)
            Exit Function
        End If
    End If
    ReDim resultBuffer(1 To dwResult)
    If (strFunc = "DECRYPT") Then
       dwRes = BCryptDecrypt(hKey, VarPtr(inputBuffer(1)), UBound(inputBuffer), pPaddingInfo, pIV, cbIV, VarPtr(resultBuffer(1)), UBound(resultBuffer), dwResult, dwPadding)
        If (dwRes <> 0) Then
            MyBCryptEncryptDecrypt = "Error in BCryptDecrypt Error code:" & Hex(dwRes)
            Exit Function
        End If
    Else
       dwRes = BCryptEncrypt(hKey, VarPtr(inputBuffer(1)), UBound(inputBuffer), pPaddingInfo, pIV, cbIV, VarPtr(resultBuffer(1)), UBound(resultBuffer), dwResult, dwPadding)
        If (dwRes <> 0) Then
            MyBCryptEncryptDecrypt = "Error in BCryptDecrypt Error code:" & Hex(dwRes)
            Exit Function
        End If
    End If
    ' for block ciphers result buffer may be block length to big to cater for IV for next block - dwResult will have correct number of bytes
    Dim finalBuffer() As Byte
    appendToByteArray finalBuffer, VarPtr(resultBuffer(1)), dwResult
    MyBCryptEncryptDecrypt = encode(CRYPT_STRING_HEXRAW, finalBuffer)
End Function
Private Function MyBCryptExportKey(ByVal hKey As LongPtr, ByVal keyType As String, ByRef toBlob() As Byte) As String
    Dim dwRes As Long, dwResult As Long, strRes As String
    dwRes = BCryptExportKey(hKey, MyNULL, StrPtr(keyType), MyNULL, 0, dwResult, 0)
    If (dwRes <> 0) Then
        strRes = "Error in exporting key" & Hex(dwRes)
        GoTo exit_MyBCryptExportKey
    End If
    ReDim toBlob(1 To dwResult)
    dwRes = BCryptExportKey(hKey, MyNULL, StrPtr(keyType), VarPtr(toBlob(1)), UBound(toBlob), dwResult, 0)
    If (dwRes <> 0) Then
        strRes = "Error in exporting key" & Hex(dwRes)
        GoTo exit_MyBCryptExportKey
    End If
    MyBCryptExportKey = ""
exit_MyBCryptExportKey:
    MyBCryptExportKey = strRes
End Function
Private Function MyBCryptGetPaddingFlags(ByVal strPadding, ByRef dwFlags As Long) As String
    MyBCryptGetPaddingFlags = ""
    If (strPadding = "PKCS1") Then
        dwFlags = BCRYPT_PAD_PKCS1
        Exit Function
    End If
    If (strPadding = "OAEP") Then
        dwFlags = BCRYPT_PAD_OAEP
        Exit Function
    End If
    ' Still here = illegal parameter
    MyBCryptGetPaddingFlags = "Illegal padding parsed"
End Function

Private Function MyBCryptSetBCryptOAEPPaddingInfo(ByRef BCryptOAEPPaddingInfo As BCRYPT_OAEP_PADDING_INFO, _
            ByVal hashAlgorithm As String, strPaddingString As String, ByRef paddingBytes() As Byte) As String
    Dim strRes As String
    strRes = decode(CRYPT_STRING_HEXRAW, strPaddingString, paddingBytes)
    If (strRes <> "") Then
        MyBCryptSetBCryptOAEPPaddingInfo = "MyBCryptOAEPPaddinginfo eror in paddingBytes input : " & strRes
        Exit Function
    End If
    BCryptOAEPPaddingInfo.algId = hashAlgorithm
    BCryptOAEPPaddingInfo.pbLabel = VarPtr(paddingBytes(1))
    BCryptOAEPPaddingInfo.cbLabel = UBound(paddingBytes)
    
 '   BCryptOAEPPaddingInfo.pbLabel = MyNULL
 '   BCryptOAEPPaddingInfo.cbLabel = 0
    
    MyBCryptSetBCryptOAEPPaddingInfo = ""
End Function
Private Sub MyBCryptInitAuthModeInfo(ByRef BCryptAuthenticatedAuthModeInfo As BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
    ' BCryptAuthenticatedAuthModeInfo is passed by ref and thus already a pointer which can be passed to ZeroMemory
    ZeroMemory BCryptAuthenticatedAuthModeInfo, LenB(BCryptAuthenticatedAuthModeInfo)
    BCryptAuthenticatedAuthModeInfo.cbSize = LenB(BCryptAuthenticatedAuthModeInfo)
    BCryptAuthenticatedAuthModeInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
End Sub
Private Function MyBCryptGetPropertyLong(ByVal hHandle As LongPtr, ByVal strProperty As String) As Long
    Dim dwResult As Long, dwRes As Long, dwWork As Long
   ' Dim s As String
    dwRes = BCryptGetProperty(hHandle, StrPtr(strProperty), VarPtr(dwResult), LenB(dwResult), dwWork, 0)
    MyBCryptGetPropertyLong = dwResult
End Function
Private Function MyBCryptGetPropertyString(ByVal pHandle As LongPtr, ByVal strProperty As String) As String
    Dim dwKeyLength As Long, dwRes As Long, s As String
    Dim byteRes() As Byte
    dwRes = BCryptGetProperty(pHandle, StrPtr(strProperty & vbNullChar), 0, 0, dwKeyLength, 0)
    If (dwRes <> 0) Then
        MyBCryptGetPropertyString = "Error in finding size of property"
        Exit Function
    End If
    ReDim byteRes(1 To dwKeyLength)
    dwRes = BCryptGetProperty(pHandle, StrPtr(strProperty & vbNullChar), VarPtr(byteRes(1)), UBound(byteRes), dwKeyLength, 0)
    If (dwRes <> 0) Then
        MyBCryptGetPropertyString = "Error in retriving property"
        Exit Function
    End If
    ReDim Preserve byteRes(1 To UBound(byteRes) - 2)
    MyBCryptGetPropertyString = byteRes
End Function

'-------------------------------------------------------------------------------------------------------
' #MyCrypt section
'-------------------------------------------------------------------------------------------------------

Private Function MyCryptDecodeObjectEx(ByVal encodingType As Long, ByVal structType As Long, ByRef inBuf() As Byte, ByRef outBuf() As Byte, Optional ByVal strDebug As String = "") As String
    Dim dwSize As Long
    Dim lRes As Long
    dwSize = UBound(inBuf)
    lRes = CryptDecodeObjectEx(encodingType, structType, VarPtr(inBuf(1)), UBound(inBuf), _
                                   0, StrPtr(vbNullString), StrPtr(vbNullString), dwSize)
    If (lRes = 0) Then
        MyCryptDecodeObjectEx = "Error in MyCryptDecordeOjbeat :" & Hex(Err.LastDllError) & strDebug
        Exit Function
    End If
    ReDim outBuf(1 To dwSize)
    lRes = CryptDecodeObjectEx(encodingType, structType, VarPtr(inBuf(1)), UBound(inBuf), _
                                   0, StrPtr(vbNullString), VarPtr(outBuf(1)), dwSize)
    If (lRes = 0) Then
        MyCryptDecodeObjectEx = "Error in MyCryptDecordeOjbeat :" & Hex(Err.LastDllError) & strDebug
        Exit Function
    End If
    
    MyCryptDecodeObjectEx = ""
End Function
Private Function MyCryptEncodeObjectEx(ByVal encodingType As Long, ByVal structType As Long, ByRef inBuf() As Byte, ByRef outBuf() As Byte, Optional ByVal strDebug As String = "") As String
    Dim dwSize As Long, lRes As Long
    lRes = CryptEncodeObjectEx(encodingType, structType, VarPtr(inBuf(1)), 0, MyNULL, MyNULL, dwSize)
    If (lRes = 0) Then
        MyCryptEncodeObjectEx = "Error in MyCryptEncodeObjec retrieving size :" & Hex(Err.LastDllError) & strDebug
        Exit Function
    End If
    ReDim outBuf(1 To dwSize)
    lRes = CryptEncodeObjectEx(encodingType, structType, VarPtr(inBuf(1)), 0, MyNULL, VarPtr(outBuf(1)), dwSize)
    If (lRes = 0) Then
        MyCryptEncodeObjectEx = "Error in MyCryptEncodeObjec getting data:" & Hex(Err.LastDllError) & strDebug
        Exit Function
    End If
    MyCryptEncodeObjectEx = ""
End Function
Private Function encode(ByVal typ As Long, ByRef inBuffer() As Byte, Optional numBytes As Long = 0) As String
    Dim lLen As Long
    Dim outString As String
    If (numBytes = 0) Then
        numBytes = UBound(inBuffer)
    End If
    If CryptBinaryToString(inBuffer(1), numBytes, typ, StrPtr(vbNullString), lLen) = 0 Then
        logError 1
    End If
    outString = String$(lLen - 1, Chr$(0))
    If CryptBinaryToString(inBuffer(1), numBytes, typ, StrPtr(outString), lLen) = 0 Then
       logError (1)
    End If
    If (typ = CRYPT_STRING_HEXRAW) Then
        encode = UCase(Left$(outString, lLen - 2))
    Else
        encode = Left$(outString, lLen - 2)
    End If
    
End Function
Private Function decode(ByVal typ As Long, ByVal inString As String, ByRef byteArray() As Byte)
    Dim lLen As Long
    Dim dwActualUsed As Long
    If (Len(inString) = 0) Then
        Exit Function
    End If
    If CryptStringToBinary(StrPtr(inString), Len(inString), typ, StrPtr(vbNullString), lLen, 0&, dwActualUsed) = 0 Then
        logError 1
        MsgBox "Error in decode of" & inString
    End If
    ReDim byteArray(1 To lLen)
    If CryptStringToBinary(StrPtr(inString), Len(inString), typ, VarPtr(byteArray(1)), lLen, 0&, dwActualUsed) = 0 Then
        logError 1
    End If
End Function


'----------------------------------------------------------------------------------------
'#HASH section
'----------------------------------------------------------------------------------------
Public Function Hash_Calculate(ByVal hashFunction As String, ByVal strHex As String) As String
    Dim dataToHash() As Byte, hashObject() As Byte, hashBuffer() As Byte
    Dim hAlgHandle As LongPtr, hHash As LongPtr
    Dim dwRes As Long, dwObjectLength, dwHashLength
    Dim strRes As String
    dwRes = BCryptOpenAlgorithmProvider(hAlgHandle, StrPtr(hashFunction & vbNullChar), 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error getting AlgoritmProvider for:" & hashFunction
        GoTo Exit_HashCalculate
    End If

    dwObjectLength = MyBCryptGetPropertyLong(hAlgHandle, "ObjectLength" & vbNullChar)
    ReDim hashObject(1 To dwObjectLength)
    dwRes = BCryptCreateHash(hAlgHandle, hHash, VarPtr(hashObject(1)), UBound(hashObject), 0, 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error in BcryptCreateHash:" & Hex(dwRes)
        GoTo Exit_HashCalculate
    End If
    
    strRes = decode(CRYPT_STRING_HEXRAW, strHex, dataToHash)
    If (strRes <> "") Then
        GoTo Exit_HashCalculate
    End If
    dwRes = BCryptHashData(hHash, VarPtr(dataToHash(1)), UBound(dataToHash), 0)
    If (dwRes <> 0) Then
        strRes = "Error in BcryptCreateHash:" & Hex(dwRes)
        GoTo Exit_HashCalculate
    End If
    ' OK let us get the hash result and return as hex string
    dwHashLength = MyBCryptGetPropertyLong(hAlgHandle, "HashDigestLength" & vbNullChar)
    ReDim hashBuffer(1 To dwHashLength)
    dwRes = BCryptFinishHash(hHash, VarPtr(hashBuffer(1)), UBound(hashBuffer), 0)
    If (dwRes <> 0) Then
        strRes = "Error in BcryptFinishHash:" & Hex(dwRes)
        GoTo Exit_HashCalculate
    End If
    strRes = encode(CRYPT_STRING_HEXRAW, hashBuffer)
Exit_HashCalculate:
    Hash_Calculate = strRes
    cleanUpAlgorithmAndKey hAlgHandle, MyNULL
    If (hHash <> MyNULL) Then
        dwRes = BCryptDestroyHash(hHash)
    End If
End Function
'------------------------------------------------------------------------------------------------------------------------
' #EC Section (Elliptip Curve)
' EC_DeriveSharedSecret - derive Shared Key from a public PEM and a private PEM
' EC_LoadPublicKey - loads an EC public key from a PEM
' EC_LoadPrivateKey - Loads an EC_Privat key from a PEM
' EC_CreatePrivatePEM - Creates an EC Private PEM from curve, public and private element
' EC_CreatePublicPEM - creas an EC public PEM from curve and public element
'-----------------------------------------------------------------------------------------------------------------------
Public Function EC_DeriveSharedSecret(ByVal strPublicKeyPEM As String, ByVal strPrivateKeyPEM As String) As String
    Dim hAlgHandle As LongPtr, hPrivateKey As LongPtr, hPublicKey As LongPtr, hSecretHandle As LongPtr
    Dim dwRes As Long, strRes As String, strAlgorithm As String, sharedSecret() As Byte

    hAlgHandle = MyNULL
    hPrivateKey = MyNULL
    hPublicKey = MyNULL
    hSecretHandle = MyNULL
    strAlgorithm = BCRYPT_ECDH_P256_ALGORITHM & vbNullChar
    dwRes = BCryptOpenAlgorithmProvider(hAlgHandle, StrPtr(strAlgorithm), 0, 0)
    If (dwRes <> 0) Then
        strRes = "Error getting AlgoritmProvider"
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    hPrivateKey = 0
    hPublicKey = 0
    strRes = EC_LoadPrivateKey(strPrivateKeyPEM, hAlgHandle, hPrivateKey)
    If (strRes <> "") Then
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    strRes = EC_LoadPublicKey(strPublicKeyPEM, hAlgHandle, hPublicKey)
    If (strRes <> "") Then
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    
    dwRes = BCryptSecretAgreement(hPrivateKey, hPublicKey, hSecretHandle, 0)
    If (dwRes <> 0) Then
        strRes = "Error in BCryptSecretAgreement" & Hex(dwRes)
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    Dim dwLength As Long
    dwRes = BCryptDeriveKey(hSecretHandle, StrPtr(BCRYPT_KDF_RAW_SECRET), 0, 0, 0, dwLength, 0)
    If (dwRes <> 0) Then
         strRes = "Error in BCryptDeriveKey" & Hex(dwRes)
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    ReDim sharedSecret(1 To dwLength)
    dwRes = BCryptDeriveKey(hSecretHandle, StrPtr(BCRYPT_KDF_RAW_SECRET), 0, VarPtr(sharedSecret(1)), UBound(sharedSecret), dwLength, 0)
    reverseEndian sharedSecret 'And we get it in little endian turn it around

    If (dwRes <> 0) Then
         strRes = "Error in BCryptDeriveKey" & Hex(dwRes)
        GoTo Error_Exit_EC_DeriveSharedSecret
    End If
    strRes = encode(CRYPT_STRING_HEXRAW, sharedSecret)
    
Error_Exit_EC_DeriveSharedSecret:
    EC_DeriveSharedSecret = strRes
    cleanUpAlgorithmAndKey hAlgHandle, hPrivateKey
    cleanUpAlgorithmAndKey MyNULL, hPublicKey
    If (hSecretHandle <> MyNULL) Then
        BCryptDestroySecret (hSecretHandle)
    End If
End Function
Private Function EC_LoadPublicKey(ByVal strKey As String, ByVal hAlgHandle As LongPtr, ByRef hKey As LongPtr) As String
    Dim keyBlob() As Byte, keyInfo() As Byte, strRes As String, dwRes As Long, BCryptEccKeyBlob As BCRYPT_ECCKEY_BLOB, keyInfoStruct As CERT_PUBLIC_KEY_INFO_SHORT
    ' Decode the PEM to DER and pack it up to a KeyInfo
    strRes = PemToKeyInfo(strKey, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, keyInfo, VarPtr(keyInfoStruct), LenB(keyInfoStruct))
    If (strRes <> "") Then
        GoTo Exit_EC_LoadPublicKey
    End If
    ' Create the EccKeyBlob for the public key
    BCryptEccKeyBlob.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC
    BCryptEccKeyBlob.cbKey = (keyInfoStruct.publicKey.cbData - 1) / 2  ' there will be 65 bytes remove first + /2 cause it is 256 bits from private side
    ' The minus 1 is since we remove the first byte in public key which is 04
    appendToByteArray keyBlob, VarPtr(BCryptEccKeyBlob), LenB(BCryptEccKeyBlob)
    appendToByteArray keyBlob, keyInfoStruct.publicKey.pbData + 1, keyInfoStruct.publicKey.cbData - 1
    
    dwRes = BCryptImportKeyPair(hAlgHandle, 0, StrPtr(BCRYPT_ECCPUBLIC_BLOB), hKey, VarPtr(keyBlob(1)), LenB(BCryptEccKeyBlob) + keyInfoStruct.publicKey.cbData - 1, 0)
    If (dwRes <> 0) Then
        strRes = "error in BCryptImportKeyPair:" & Hex(dwRes)
        GoTo Exit_EC_LoadPublicKey
    End If
    EC_LoadPublicKey = ""
    Exit Function
Exit_EC_LoadPublicKey:
        EC_LoadPublicKey = strRes ' Cleanup handled in calling function
End Function
Private Function EC_LoadPrivateKey(ByVal strPrivateKey As String, ByVal hAlgHandle As LongPtr, ByRef hKey As LongPtr) As String
    Dim keyInfo() As Byte, keyBlob() As Byte, strRes As String, dwRes As Long, BCryptEccKeyBlob As BCRYPT_ECCKEY_BLOB, keyInfoStruct As CRYPT_ECC_PRIVATE_KEY_INFO
    ' Decode the PEM to DER and pack it up to a KeyInfo
    strRes = PemToKeyInfo(strPrivateKey, XorDWord(X509_ASN_ENCODING, PKCS_7_ASN_ENCODING), X509_ECC_PRIVATE_KEY, keyInfo, VarPtr(keyInfoStruct), LenB(keyInfoStruct))
    If (strRes <> "") Then
        GoTo Exit_EC_LoadPrivateKey
    End If
    ' Build blob BCryptEccKeyBlob + public key (not first byte) and then prrivate key. The minus 1 is since we remove the first byte in public key which is 04
    BCryptEccKeyBlob.dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC
    BCryptEccKeyBlob.cbKey = keyInfoStruct.privateKey.cbData
    appendToByteArray keyBlob, VarPtr(BCryptEccKeyBlob), LenB(BCryptEccKeyBlob)
    appendToByteArray keyBlob, keyInfoStruct.publicKey.pbData + 1, keyInfoStruct.publicKey.cbData - 1
    appendToByteArray keyBlob, keyInfoStruct.privateKey.pbData, keyInfoStruct.privateKey.cbData
    
    dwRes = BCryptImportKeyPair(hAlgHandle, 0, StrPtr(BCRYPT_ECCPRIVATE_BLOB), hKey, VarPtr(keyBlob(1)), UBound(keyBlob), 0)
    If (dwRes <> 0) Then
        strRes = "error in BCryptImportKeyPair:" & Hex(dwRes)
        GoTo Exit_EC_LoadPrivateKey
    End If
    EC_LoadPrivateKey = ""
    Exit Function
Exit_EC_LoadPrivateKey:
    EC_LoadPrivateKey = strRes ' Cleanup handled in calling function
End Function
Public Function EC_CreatePublicPEM(ByVal curve As String, ByVal publicKey) As String
    Dim OID As String, oidStr As String, pubStr As String, full As String
    OID = ASN_getOID(curve)
    oidStr = ASN_getTag("30", ASN_getTag("06", OID))
    pubStr = ASN_getTag("03", "00" & publicKey)
    full = ASN_getTag("30", oidStr & pubStr)
    EC_CreatePublicPEM = "-----BEGIN PUBLIC KEY-----" & _
                            Util_HexStrToBase64(full) & _
                          "-----END PUBLIC KEY-----"
End Function
Public Function EC_CreatePrivatePEM(ByVal curve As String, ByVal publicKey, ByVal privateKey As String) As String
    Dim OID As String, oidStr As String, pubStr As String, full As String, privstr As String
    OID = ASN_getOID(curve)
    oidStr = ASN_getTag("A0", ASN_getTag("06", OID))
    pubStr = ASN_getTag("A1", ASN_getTag("03", "00" & publicKey))
    privstr = ASN_getTag("04", privateKey)
    
    full = ASN_getTag("30", "020101" & privstr & oidStr & pubStr)
    EC_CreatePrivatePEM = "-----BEGIN EC PRIVATE KEY-----" & _
                            Util_HexStrToBase64(full) & _
                          "-----END EC PRIVATE KEY-----"
End Function
'-------------------------------------------------
'Utility functions
'
'
'-------------------------------------------------
Private Function PemToKeyInfo(ByVal strPem As String, ByVal dwEncoding As Long, ByVal pszStructType As String, ByRef keyInfo() As Byte, ByVal pKeyInfo As LongPtr, ByVal cbKeyInfo As Long) As String
    Dim strRes As String
    Dim derBuffer() As Byte
    Dim dwRes As Long
    strRes = decode(CRYPT_STRING_BASE64HEADER, strPem, derBuffer)
    If (strRes <> "") Then
        GoTo Exit_PemToKeyInfo
    End If
    strRes = MyCryptDecodeObjectEx(dwEncoding, pszStructType, derBuffer, keyInfo)
    If (strRes <> "") Then
        GoTo Exit_PemToKeyInfo
    End If
    If (cbKeyInfo > UBound(keyInfo)) Then
        strRes = "Key info is not large enough"
        GoTo Exit_PemToKeyInfo
    End If
    CopyMemory pKeyInfo, VarPtr(keyInfo(1)), cbKeyInfo
    PemToKeyInfo = ""
    Exit Function
Exit_PemToKeyInfo:
    PemToKeyInfo = strRes
End Function
Public Sub reverseEndian(ByRef inArr() As Byte)
    Dim tempArr() As Byte
    Dim i As Integer
    ReDim tempArr(1 To UBound(inArr))
    CopyMemory VarPtr(tempArr(1)), VarPtr(inArr(1)), UBound(inArr)
    For i = 1 To UBound(tempArr)
        inArr(i) = tempArr((UBound(tempArr) + 1) - i)
    Next
End Sub
Private Function varToHexstr(ByVal structPtr As LongPtr, ByVal lenBytes As Long) As String
    Dim buffer() As Byte
    ReDim buffer(1 To lenBytes)
    CopyMemory VarPtr(buffer(1)), structPtr, lenBytes
    varToHexstr = encode(CRYPT_STRING_HEXRAW, buffer)
End Function
Private Function XorDWord(ByVal xor1 As Long, ByVal xor2 As Long) As Long
    Dim bXor1(1 To 4) As Byte, bXor2(1 To 4) As Byte, res() As Byte
    Dim dwRes As Long
    Dim strRes As String
    dwRes = 0
    CopyMemory VarPtr(bXor1(1)), VarPtr(xor1), 4
    CopyMemory VarPtr(bXor2(1)), VarPtr(xor2), 4
    strRes = varToHexstr(VarPtr(bXor1(1)), 4)
    strRes = varToHexstr(VarPtr(bXor2(1)), 4)
    If (Xorbuffer(bXor1, bXor2, res) = "") Then
        CopyMemory VarPtr(dwRes), VarPtr(res(1)), 4
    Else
        ' TBD throw exection
    End If
    XorDWord = dwRes
End Function
Private Function Xorbuffer(ByRef xor1() As Byte, ByRef xor2() As Byte, ByRef res() As Byte) As String  ' Assumes 1 to ubound
    Dim i As Long
    If (UBound(xor1) <> UBound(xor2)) Then
        Xorbuffer = "XorBuffer - Size of xor1 <> xor2"
        Exit Function
    End If
    ReDim res(1 To UBound(xor1))
    For i = 1 To UBound(xor2)
        res(i) = xor1(i) Xor xor2(i)
    Next
    Xorbuffer = ""
End Function
Private Function HexStrToVar(ByVal hexStr As String, ByVal var As LongPtr, ByVal numBytes As Integer)
    Dim buffer() As Byte
    decode CRYPT_STRING_HEXRAW, hexStr, buffer
    CopyMemory var, VarPtr(buffer(1)), numBytes
End Function
'---------------------------------------------------------------------------------
' Symmetric sections
' AES_Encrypt - encrypt using AES a block of date
' AES_Decrypt - decrypt using AES a block of date
' DES_Encrypt - encrypt using DES a block of date
' DES_Encrypt - denrypt using DES a block of date
' GCM_getEncrypted - get the actual encrypted block after encryption
' GCM_getTag - get the tag (stored after the encrypted data)
'----------------------------------------------------------------------------------

Public Function AES_Encrypt(ByVal key As String, ByVal plain As String, Optional ByVal mode As String = "CBC", Optional ByVal iv As String = "") As String
    AES_Encrypt = DoCrypt("AES", "ENCRYPT", plain, key, mode, iv)
End Function
Public Function AES_Decrypt(ByVal key As String, ByVal cipher As String, Optional ByVal mode As String = "CBC", Optional ByVal iv As String = "", Optional ByVal GCMtagLen As Long = 12) As String
    AES_Decrypt = DoCrypt("AES", "DECRYPT", cipher, key, mode, iv, GCMtagLen)
End Function
Public Function DES_Encrypt(ByVal key As String, ByVal plain As String, Optional ByVal mode As String = "CBC", Optional ByVal iv As String = "") As String
    DES_Encrypt = DoCrypt("DES", "ENCRYPT", plain, key, mode, iv)
End Function
Public Function DES_Decrypt(ByVal key As String, ByVal cipher As String, Optional ByVal mode As String = "CBC", Optional ByVal iv As String = "") As String
    DES_Decrypt = DoCrypt("DES", "DECRYPT", cipher, key, mode, iv)
End Function
Private Function DoCrypt(ByVal algorithm As String, ByVal func As String, ByVal inString As String, ByVal key As String, Optional ByVal mode As String = "CBC", _
        Optional ByVal iv As String = "", Optional ByVal GCMtagLen As Long) As String
    Dim strRes As String, strProperty As String, strPropertyValue As String, GCMTag As String
    Dim keyBuffer() As Byte, inBuffer() As Byte, ivBuffer() As Byte, keyObject() As Byte, authTag() As Byte, nonceBytes() As Byte
    Dim cbKeyObject As Long, cbBlockLength As Long, lRes As Long, dwResult As Long, dwFlags As Long, cbIV As Long
    Dim phalgorithm As LongPtr, phkey As LongPtr, pPaddingInfo As LongPtr, pIV As LongPtr
    Dim BCryptAuthenticatedAuthModeInfo As BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, authTagLengths As BCRYPT_AUTH_TAG_LENGTHS_STRUCT

    phkey = MyNULL
    phalgorithm = MyNULL
    If (algorithm = "DES") Then
        If Len(key) = 48 Then '3DES
            algorithm = "3DES"
        Else
            If Len(key) = 32 Then 'double des
                algorithm = "3DES_112"
            Else
                If Len(key) <> 16 Then
                    strRes = "Illegal key length for DES in DoCrypt should be 8, 16 or 24 bytes "
                    GoTo Exit_DoCrypt
                End If
            End If
        End If
    End If
    
    strRes = decode(CRYPT_STRING_HEXRAW, key, keyBuffer)
    If (strRes <> "") Then
        strRes = "Error decoding key in DoCrypt " & strRes
        GoTo Exit_DoCrypt
    End If
    ' for GCM split the instring in the part which is the encoded buffer and the GCMtag
    If (mode = "GCM") Then 'split the inString in the encoded buffer and the GCMtag
        GCMTag = GCM_getTag(inString, GCMtagLen)
        inString = GCM_getEncrypted(inString, GCMtagLen)
    End If
    strRes = decode(CRYPT_STRING_HEXRAW, inString, inBuffer)
    If (strRes <> "") Then
        strRes = "Error decoding inBuffer in DoCrypt " & strRes
        GoTo Exit_DoCrypt
    End If
    strRes = decode(CRYPT_STRING_HEXRAW, iv, ivBuffer)
    If (strRes <> "") Then
        strRes = "Error decoding IV in DoCrypt " & strRes
        GoTo Exit_DoCrypt
    End If
  
    lRes = BCryptOpenAlgorithmProvider(phalgorithm, StrPtr(algorithm & vbNullChar), 0, 0)
    If (lRes <> 0) Then
        strRes = "Error getting algorithm provider in DoCrypt" & Hex(lRes)
        GoTo Exit_DoCrypt
    End If
    strProperty = "ObjectLength" & vbNullChar
    lRes = BCryptGetProperty(phalgorithm, StrPtr(strProperty), VarPtr(cbKeyObject), LenB(cbKeyObject), dwResult, 0)
    If (lRes <> 0) Then
        strRes = "Error getting object length in DoCrypt " & Hex(lRes)
        GoTo Exit_DoCrypt
    End If
    ReDim keyObject(1 To cbKeyObject) 'Allocate size for key object
     
    strProperty = "BlockLength" & vbNullChar
    lRes = BCryptGetProperty(phalgorithm, StrPtr(strProperty), VarPtr(cbBlockLength), LenB(cbBlockLength), dwResult, 0)
    If (lRes <> 0) Then
        strRes = "Error getting BlockLength in DoCrypt " & Hex(lRes)
        GoTo Exit_DoCrypt
    End If
    
    strProperty = "ChainingMode" & vbNullString
    strPropertyValue = "ChainingMode" & mode & vbNullString
    lRes = BCryptSetProperty(phalgorithm, StrPtr(strProperty), ByVal StrPtr(strPropertyValue), LenB(strPropertyValue), 0)
    If (lRes <> 0) Then
        strRes = "Error setting ChainingMode in DoCrypt " & Hex(lRes)
        GoTo Exit_DoCrypt
    End If
    
    lRes = BCryptGenerateSymmetricKey(phalgorithm, phkey, keyObject(1), cbKeyObject, keyBuffer(1), UBound(keyBuffer), 0)
    If (lRes <> 0) Then
        strRes = "Error generating symmetric key  in DoCrypt " & Hex(lRes)
        GoTo Exit_DoCrypt
    End If
    If (mode = "ECB" Or mode = "GCM") Then
        pIV = MyNULL
        cbIV = 0
    Else
        pIV = VarPtr(ivBuffer(1))
        cbIV = UBound(ivBuffer)
    End If
    pPaddingInfo = MyNULL
    dwFlags = BCRYPT_BLOCK_PADDING  ' Assume not GCM
    If (mode = "GCM") Then
        dwFlags = 0 'Override dwFlags
        lRes = BCryptGetProperty(phalgorithm, StrPtr(BCRYPT_AUTH_TAG_LENGTH), VarPtr(authTagLengths), LenB(authTagLengths), dwResult, 0)
        If (lRes <> 0) Then
            strRes = "Error retrieving AuthTaglenght in DoCrypt:" & Hex(lRes)
            GoTo Exit_DoCrypt
        End If
        pPaddingInfo = VarPtr(BCryptAuthenticatedAuthModeInfo)
        MyBCryptInitAuthModeInfo BCryptAuthenticatedAuthModeInfo
        strRes = decode(CRYPT_STRING_HEXRAW, iv, nonceBytes)
        If (strRes <> "") Then
            GoTo Exit_DoCrypt
        End If
        BCryptAuthenticatedAuthModeInfo.pbNonce = VarPtr(nonceBytes(1))
        BCryptAuthenticatedAuthModeInfo.cbNonce = UBound(nonceBytes)
        If (func = "ENCRYPT") Then
            ReDim authTag(1 To authTagLengths.dwMinLength) 'Make room for the AuthTag
        Else
            appendHexStrToByteArray authTag, GCMTag ' Set the AuthTag to value passed
            If (strRes <> "") Then
                strRes = "Error setting the GCM tac in DoCrypt:" & strRes
                GoTo Exit_DoCrypt
            End If
        End If
        BCryptAuthenticatedAuthModeInfo.pbTag = VarPtr(authTag(1))
        BCryptAuthenticatedAuthModeInfo.cbTag = UBound(authTag)
    End If
    
    strRes = MyBCryptEncryptDecrypt(func, inBuffer, phkey, dwFlags, pIV, cbIV, pPaddingInfo)
    If (mode = "GCM" And func = "ENCRYPT") Then
        strRes = strRes & encode(CRYPT_STRING_HEXRAW, authTag, UBound(authTag))
    End If
    
Exit_DoCrypt:
    DoCrypt = strRes
    cleanUpAlgorithmAndKey phalgorithm, phkey
End Function
Public Function GCM_getEncrypted(ByVal inString, Optional ByVal tagLen As Long = 12) As String
    GCM_getEncrypted = Mid(inString, 1, Len(inString) - (2 * tagLen))
End Function
Public Function GCM_getTag(ByVal inString, Optional ByVal tagLen As Long = 12) As String
     GCM_getTag = Mid(inString, 1 + Len(inString) - (2 * tagLen), 2 * tagLen)
End Function

Private Sub cleanUpAlgorithmAndKey(ByVal phalgorithm As LongPtr, ByVal phkey As LongPtr)
    Dim lRes As Long
    If phalgorithm <> MyNULL Then
        lRes = BCryptCloseAlgorithmProvider(phalgorithm, 0)
        If (lRes <> 0) Then
            logError lRes
        End If
    End If
    If (phkey <> MyNULL) Then
        lRes = BCryptDestroyKey(phkey)
        If (lRes <> 0) Then
            logError lRes
        End If
    End If
End Sub

Private Sub logError(ByVal result As Long)
    Debug.Print "result:" & Hex(result) & " Desc" & Err.Description & " lastDll:" & Hex(Err.LastDllError)
End Sub
Private Function isArrayEmpty(ByRef byteArray() As Byte) As Boolean
'https://software-solutions-online.com/vba-check-for-empty-array/
    isArrayEmpty = (StrPtr(byteArray) = 0)
End Function
Private Function rightPad(ByVal value As String, ByVal width As Integer, ByVal padChar As String)
    rightPad = Right(String(width, padChar) & value, width)
End Function
Private Function appendToByteArray(ByRef toBuffer() As Byte, ByVal pbFrom As LongPtr, ByVal cbLength)
    Dim toIndex As Long
    If (isArrayEmpty(toBuffer)) Then
        toIndex = 1
        ReDim toBuffer(1 To cbLength)
    Else
        toIndex = UBound(toBuffer) + 1
        ReDim Preserve toBuffer(1 To toIndex + cbLength - 1)
    End If
    CopyMemory VarPtr(toBuffer(toIndex)), pbFrom, cbLength
End Function
Private Function extractBytesToHexStr(ByRef byteArray() As Byte, ByVal startIndex As Integer, ByVal Length As Integer) As String
    Dim target() As Byte
    ReDim target(1 To Length)
    CopyMemory VarPtr(target(1)), VarPtr(byteArray(startIndex)), Length
    extractBytesToHexStr = encode(CRYPT_STRING_HEXRAW, target)
End Function
Private Sub appendHexStrToByteArray(ByRef byteArray() As Byte, ByVal hexStr As String)
    Dim bytesToAdd() As Byte
    Dim strRes As String
    strRes = decode(CRYPT_STRING_HEXRAW, hexStr, bytesToAdd)
    If (strRes <> "") Then
        MsgBox "Error in appendHexStrToByteArray bad hexstring" & hexStr
        Exit Sub
    End If
    appendToByteArray byteArray, VarPtr(bytesToAdd(1)), UBound(bytesToAdd)
End Sub
'----------------------------------------------
' ASN functions
'-------------------------------------------------
Private Function ASN_addLeadingZero(ByVal hexStr As String) As String
    If (Mid(hexStr, 1, 2) > "7F") Then
        ASN_addLeadingZero = "00" & hexStr
    Else
        ASN_addLeadingZero = hexStr
    End If
End Function
Private Function ASN_removeLeadingZero(ByVal str As String) As String
    If (Mid(str, 1, 2) = "00") Then
        ASN_removeLeadingZero = Mid(str, 3, Len(str) - 2)
    Else
        ASN_removeLeadingZero = str
    End If
End Function
Private Function ASN_getTag(ByVal tag As String, ByVal hexStringValue As String) As String
    Dim bytelen As Integer
    Dim strRes As String
    bytelen = Len(hexStringValue) / 2
    If (bytelen > 255) Then
        strRes = tag & "82" & rightPad(Hex(bytelen), 4, "0") & hexStringValue
    Else
        If (bytelen > 127) Then
            strRes = tag & "81" & rightPad(Hex(bytelen), 2, "0") & hexStringValue
        Else
            strRes = tag & rightPad(Hex(bytelen), 2, "0") & hexStringValue
        End If
    End If
    ASN_getTag = strRes
End Function

Private Function ASN_getOID(ByVal keyOID) As String
' couldn't find an easy way to initialize a collection or dictionary . so use an array when key found value is a next element (i+1)
    Dim strOIDS As String
    Dim strOIDArr() As String
    Dim i As Integer
    keyOID = UCase(keyOID)
    strOIDS = "RSA,2A864886F70D010101,PRIME256V1,2A8648CE3D030107"
    strOIDArr = Split(Replace(strOIDS, " ", ""), ",")  'Remove blanks and create arr of strings seperated by commas ,
    For i = 0 To UBound(strOIDArr) - 1 Step 2
        If (strOIDArr(i) = keyOID) Then
            ASN_getOID = strOIDArr(i + 1)
            Exit Function
        End If
    Next
    ASN_getOID = ""  ' stilll here means not found
End Function
'----------------------------------------------------------------------------------
'#Util section
'----------------------------------------------------------------------------------
Public Function Util_hexstrReverse(ByVal hexStr As String) As String
    Dim buffer() As Byte
    decode CRYPT_STRING_HEXRAW, hexStr, buffer
    reverseEndian buffer
    Util_hexstrReverse = encode(CRYPT_STRING_HEXRAW, buffer)
End Function

Public Function Util_hexStrToAscii(ByVal hexStr As String) As String
    Dim buffer() As Byte
    Dim strRes As String
    Dim i As Integer
    strRes = decode(CRYPT_STRING_HEXRAW, hexStr, buffer)
    If (strRes <> "") Then
        GoTo exit_hexStrToAscii
    End If
    For i = 1 To UBound(buffer)
        strRes = strRes & Chr(buffer(i))
    Next
exit_hexStrToAscii:
    Util_hexStrToAscii = strRes
End Function
Public Function Util_AsciiToHexStr(ByVal strAscii) As String
    Dim res As String
    Dim i As Integer
    res = ""
    For i = 1 To Len(strAscii)
            res = res & rightPad(Hex(Asc(Mid(strAscii, i, 1))), 2, "0")
    Next
    Util_AsciiToHexStr = res
End Function
Public Function Util_showFormula(ByVal cell As Range) As String
    Util_showFormula = cell.Formula
End Function
Public Function Util_HexOverUnderToHexStr(ByVal s1 As String, ByVal s2 As String) As String
    Dim res As String
    Dim i As Long
    res = ""
    For i = 1 To Len(s1)
        res = res & Mid(s1, i, 1) & Mid(s2, i, 1)
   Next
    Util_HexOverUnderToHexStr = res
End Function


Public Function Util_HexStrToBase64(ByVal hexStr As String) As String
    Dim inBuffer() As Byte
    decode CRYPT_STRING_HEXRAW, hexStr, inBuffer
    Util_HexStrToBase64 = encode(CRYPT_STRING_BASE64, inBuffer)
End Function
Public Function Util_Base64ToHexStr(ByVal base64str As String) As String
    Dim inBuffer() As Byte
    If (Mid(base64str, 1, 2) = "--") Then ' It has a header
        decode CRYPT_STRING_BASE64HEADER, base64str, inBuffer
    Else
        decode CRYPT_STRING_BASE64, base64str, inBuffer
    End If
    Util_Base64ToHexStr = encode(CRYPT_STRING_HEXRAW, inBuffer)
End Function
Public Function Util_GenRandom(ByVal size As Long) As String
    Dim buffer() As Byte
    Dim dwRes As Long
    ReDim buffer(1 To size)
    dwRes = BCryptGenRandom(MyNULL, VarPtr(buffer(1)), UBound(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    If (dwRes <> 0) Then
        Util_GenRandom = "Error in gererate random:" & Hex(dwRes)
        Exit Function
    End If
    Util_GenRandom = encode(CRYPT_STRING_HEXRAW, buffer)
End Function


