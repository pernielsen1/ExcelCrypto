import sys
import base64
keyfile = "/input/aeskey.base64"
ivfile = "/input/iv.base64"
plainfile = "/input/plain.txt"
def base64_file_tobin(infile):
    
# if (len(sys.argv) != 3):
#    print("wrong number of args - usage python3 utils_base64tobin.py <base64InFile> <binOutFile>")
#    sys.exit(1)
# still hera all is good  
keybytes = base64.b64decode(keyfile)
fin = open(sys.argv[1], mode="rb")
data = fin.read() 
fin.close()
