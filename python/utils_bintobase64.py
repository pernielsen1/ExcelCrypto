import sys
import base64
if (len(sys.argv) != 3):
    print("wrong number of args - usage python3 utils_bintobase64.py <binInFile> <base64OutFile>")
    sys.exit(1)
# still hera all is good  

# Opening the binary in file in binary mode as rb(read binary) and read all data to data variable
fin = open(sys.argv[1], mode="rb")
data = fin.read() 
fin.close()
# convert the read bytes to base64
convertedbytes = base64.b64encode(data)
# write the converted bytes to out file
fout = open(sys.argv[2], mode="wb")
fout.write(convertedbytes)
fout.close