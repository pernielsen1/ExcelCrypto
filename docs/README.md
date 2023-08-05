# ExcelCrypto
## What is ExcelCrypto

An implementation of Excel VBA macros exposing Crypto calculations as Excel Formulas.  Functions available for Encryption and Decryption using AES, DES, RSA and EC (Ellitic curve) algorithms as well as signature creation and verification 

## Why is ExcelCrypto usefull ?
When doing crypto development you will often be working with an external party. It is usefull to have a tool where test vectors can be easily created and documented on the same time  - writing an Excel Formula like =RSA_Encrypt(A2, B2, "PKCS1") where A2 contains a PEM public key and B2 data to be encrypted in hexstring notation and getting back a hex string is rather self explanatory 

## Getting started
Goto [ExcelExampleAndMakroSource directory](../ExcelExampleAndMakroSource)
- Download the Excel file (which is not makro enabled) ExcelCryptoNoMakro.xlsx
- Download the VBA source file CNG_Functions.bas
- Open the Excel file and do File->save a copy,  change the type from Excel Workbook (.xlsx) to Excel Macro Enabled workbook  (.xlsm) and give it a different name like ExcelExampleWithMacro.xlsm - press save.
- Check your tabs in the top of Excel window do you have a Developer menu (just before help probably) if not enable it see here how to do it. 
- Press alt-F11 - that will bring you into the VBA Editor. 
- Choose File->Import File - navigate to where you stored the "CNG_Functions.bas" file - select it and choose open
- Go back to the excel sheets, press save, and you are ready to go

You will be in start here which is a good place to start.
You can safely delete the remaining sheets - they are only for example purposes.






Alice and Bob scenarios

Also includes Alice & Bob messaging using RSA/EC to exchange with AES keys and encrypted messages and signature. 
Includes apart from standard RSA PKCS1 also OAEP. For AES both PKCS7 and GCM padding implemented-

