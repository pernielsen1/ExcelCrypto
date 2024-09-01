#-----------------------------------------------------------
# test the getpass
#-----------------------------------------------------------
import getpass
print("User is:" + getpass.getuser())
password = getpass.getpass("Enter password")
print("password was:" + password + ":")
