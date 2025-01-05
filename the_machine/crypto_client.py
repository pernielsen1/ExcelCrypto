# crypto test cases


import os
import json
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
import crypto_client

key_name="IMK_k1"
IMK_k1="0123456789abcdeffedcba9876543210"
PAN = "5656781234567891"
PSN = "01"
ATC = "0001"
data =  "00000000510000000000000007920000208000094917041900B49762F2390000010105A0400000200000000000000000"
data_with_80 = "00000000510000000000000007920000208000094917041900B49762F2390000010105A040000020000000000000000080"
expected_result = "F5EB72ED4F51B9DE" 

#------------------ GLOBALS ---------------------------
config_dir = 'crypto/'
config_file = 'test_crypto.json'

# segment_to_run = 'ALL'


crypto_handle = None # just a dummy global object
#------------------------------------------------------------
# crypto_jsd - defining interface to crypto package
#-------------------------------------------------------------
class crypto_hsm:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, name):
        self.name = name
    def get_name(self):
        return self.name
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    #-------------------------------------------------------------
    # do_DES
    #-------------------------------------------------------------
    def do_DES(self, operation, key_value, mode, data, iv):
        if len(key_value) == 32 :
            key_value = key_value + key_value[0: 16]  # double des set k3 = K1 

        if (len(key_value) == 16):
            des_obj = DES
        else:
            des_obj = DES3

        key_token = bytes.fromhex(key_value)

        if (mode == "ECB" and operation != 'mac'):
            cipher_obj = des_obj.new(key_token, des_obj.MODE_ECB)
        if (mode == "CBC" and operation != 'mac'):
            iv_bin = bytes.fromhex(iv)
            cipher_obj = des_obj.new(key_token, des_obj.MODE_CBC, iv=iv_bin)

        data_bin = bytes.fromhex(data)
        if (operation == "encrypt"):
            return cipher_obj.encrypt(data_bin).hex()
        if (operation == "decrypt"):
            return cipher_obj.decrypt(data_bin).hex()
        if (operation == "mac"):
            cobj = CMAC.new(key_token, ciphermod=des_obj)
            cobj.update(data_bin)
            return cobj.hexdigest()
        # still here something wrong 
        return "Invalid operation"

#-------------------------------------------------------------
# udk
#-------------------------------------------------------------
def do_udk(imk, pan, psn):
    pan_psn = pan + psn;
    pan_psn = pan_psn[len(pan_psn) -16: len(pan_psn)]
    iv = "0000000000000000"
    left  = crypto_handle.do_DES('encrypt', imk, 'ECB', pan_psn, iv)
    pan_psn_xor = hex_string_xor(pan_psn, "FFFFFFFFFFFFFFFF")
    right = crypto_handle.do_DES('encrypt', imk, 'ECB', pan_psn_xor, iv)
    return left + right
#-------------------------------------------------------------
# session_key
#-------------------------------------------------------------
def do_session_key(imk, pan, psn, atc):
    udk  = do_udk(imk, pan, psn)
    r = atc + "000000000000"
    f1 = atc + "F0" + "0000000000"
    f2 = atc + "0F" + "0000000000"
    iv = "0000000000000000"
    left  = crypto_handle.do_DES('encrypt', udk, 'ECB', f1, iv)
    right = crypto_handle.do_DES('encrypt', udk, 'ECB', f2, iv)
    return left + right
#------------------------------------------------------------
# mypad: do an EMV pad
#------------------------------------------------------------
def mypad(data, block_size):
    num_to_pad = block_size - (len(data) % block_size)
    eight_zeroes = "0000000000000000" 
    if (num_to_pad == block_size):
        return data
    else: 
        eight_zeroes = "0000000000000000" 
        pad_data = eight_zeroes[0: num_to_pad]
        return data + pad_data
#-------------------------------------------------------------
# do_arqc
#-------------------------------------------------------------
def man_mac(key, data):
    left = key[0:16]
    num_iter = int(len(data) / 16) - 1
    iv = "0000000000000000"
    data_block = data[0:16]
    for i in range(num_iter):
        data_block = crypto_handle.do_DES('encrypt', left, 'ECB', data_block, iv)
        xor1 = data_block
        start = (i + 1) * 16
        xor2 = data[start: start  + 16]
        data_block = hex_string_xor(xor1, xor2)
    return data_block
            
def do_arqc(imk, pan, psn, atc, data, add80):
    sk = do_session_key(imk, pan, psn, atc)
    if (add80):
        data = data + "80"
    data = mypad(data, 16)
    iv = "0000000000000000"
    left = sk[0:16]
    # do a normal DES CBC encrypt of all blocks except the last block
    mac_data = data[0: len(data) - 16]
    enc2 = crypto_handle.do_DES('encrypt', left, 'CBC', mac_data, iv)
    # take last block of encrypted data and xor with the last block of the data (last 8 bytes)
    last_block_in_enc = enc2[len(enc2) - 16:len(enc2)]
    last_plain_block = data[len(data)-16:len(data)]
    enc_mac = hex_string_xor(last_plain_block, last_block_in_enc)
    man_mac_val = man_mac(sk, data)
    arqc = crypto_handle.do_DES('encrypt', sk, 'CBC', enc_mac, iv)
    return arqc 


#---------------------------------------------------------------------
# hex_string_xor(s1, s2)
# https://stackoverflow.com/questions/52851023/python-3-xor-bytearrays
#---------------------------------------------------------------------
def hex_string_xor(s1, s2):
    one = bytes.fromhex(s1)
    two = bytes.fromhex(s2)
    one_xor_two = bytes(a ^ b for (a, b) in zip(one, two))
    return one_xor_two.hex()

#-------------------------------------------------------
# init
#------------------------------------------------------
def crypto_client_init():
    global crypto_handle
    crypto_handle = crypto_hsm("my_hsm")

#-------------------------------------------
# run_test: Run a crypto test case
#-------------------------------------------
def run_test():
    result_str= do_arqc(IMK_k1, PAN, PSN, ATC, data, True  )
    if (result_str == expected_result.lower()):
        return 1 
    else:
        return 0
# here we go
# print('current directory:' + os.getcwd())
# run_test()