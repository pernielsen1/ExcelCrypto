import os
x=0o777

print(str(x))
x=os.umask(0o777)
print(str(x))
b=hex(x)
print(b)
