import sys
import base64
if (len(sys.argv) != 3):
    print("wrong number of args - usage python3 utils_hexstrtobin.py <hexstrInFile> <binOutFile>")
    sys.exit(1)
# still hera all is good  
# Opening the binary in file in binary mode as rb(read binary) and read all data to data variable
fin = open(sys.argv[1], mode="rb")
data = fin.read() 
fin.close()
# convert the read bytes to base64
resArray = bytearray.fromhex(data.decode("ascii"))
# write the converted bytes to out file
fout = open(sys.argv[2], mode="wb")
fout.write(resArray)
fout.close