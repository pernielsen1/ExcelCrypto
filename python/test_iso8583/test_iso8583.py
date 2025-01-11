# pip install pyiso8583
# https://pyiso8583.readthedocs.io/en/latest/?badge=latest

import pprint
import iso8583

from my_specs import my_default as spec

def do_it():
    encoded_raw = bytes.fromhex('303130304000000000000000313031323334353637383930')
    print(encoded_raw.hex())
    decoded, encoded = iso8583.decode(encoded_raw, spec)
    pprint.pp(decoded)

#-----------------------------------------------------------------------------------------
# num_fixed: helper function making numeric fiedd of fixed len with zero fill to the left
#------------------------------------------------------------------------------------------
def num_fixed(s, len):
    return s.zfill(len)[:len]
#-------------------------------------------------
# build_msg:  builds a test iso8583 message
#--------------------------------------------------
def build_msg():
    decoded = {'t': '0100'}
    decoded['2'] = '1234567890'
    encoded_raw, encoded = iso8583.encode(decoded, spec)
    pprint.pp(encoded)
    print("hex:" + encoded_raw.hex())
    decoded['2'] = '1234567890'
    decoded['3'] = '111111'
    decoded['4'] = num_fixed('1234',12)
    decoded['21'] = '021'
    encoded_raw, encoded = iso8583.encode(decoded, spec)
    pprint.pp(encoded)
    return encoded_raw 

#----------------------------------------------------------------------
# decode_msg: Decode the byte array msg_raw
#------------------------------------------------------------------------
def decode_msg(msg_raw):
    print("Decoding:" + msg_raw.hex())
    decoded, encoded = iso8583.decode(msg_raw, spec)
    pprint.pp(decoded)

# here we go
msg_raw = build_msg()
decode_msg(msg_raw)
