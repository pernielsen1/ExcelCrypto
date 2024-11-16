# The logic module building the reply message based on rules
import json

def build_reply_msg(msg_str):
    msg = json.loads(msg_str)
    msg['msg_code'] = "0110"
    msg['f038'] = "654321"
    msg['f039'] = "00"
    return msg
