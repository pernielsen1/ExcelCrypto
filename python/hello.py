import pandas as pd
import os
import shutil
import datetime
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest'
config_dir='/home/perni/ExcelCrypto/python/config'
out_dir='/home/perni/ExcelCrypto/python/output'
big_dir='/home/perni/ExcelCrypto/python/big'
       
def clear_dir(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def write_csv(folder_name, file_name, df):
    df.to_csv(folder_name + '/' + file_name + '.csv', sep=';', encoding='utf-8', index=False)
    
def build_big(numc1, numc2):
    clear_dir(big_dir)
    c1_df= pd.DataFrame(columns=['ID','NAME'])
    c2_df= pd.DataFrame(columns=['ID','NAME2'])
    c3_df= pd.DataFrame(columns=['ID','ADDR1'])
    for i in range(0, numc1):
        c1_df.loc[len(c1_df)] = [i,  "My Number Name is:" + str(i)]
        c3_df.loc[len(c3_df)] = [i,  "My C1 Address is:" + str(i)]
    # write record in c1 not in c3
    c1_df.loc[len(c1_df)] = [42000001,  "My Number Name is: not in C3"]     
    for i in range(numc1, numc1 + numc2):
        c2_df.loc[len(c2_df)] = [i,  "My Number Name is:" + str(i)]
        c3_df.loc[len(c3_df)] = [i,  "My C2 Address is:" + str(i)]
    # write record in c2 not in c3
    c2_df.loc[len(c2_df)] = [42000002,  "My Number Name is: not in C3"]
    # write record in c3 not in c1 nor c2
    c3_df.loc[len(c3_df)] = [42000003,  "My C3 address is non in C1 nor C2:"]

    c1_df.to_csv(big_dir + '/' + 'C1.csv', sep=';', encoding='utf-8', index=False)
    c2_df.to_csv(big_dir + '/' + 'C2.csv', sep=';', encoding='utf-8', index=False)
    c3_df.to_csv(big_dir + '/' + 'C3.csv', sep=';', encoding='utf-8', index=False)

    print("Done")
def log(msg):
    now = datetime.datetime.now()
    print(msg, now.strftime("%Y-%m-%d, %H:%M:%S"))

def write_row(out_file, rec_type, id, name, addr1): 
    record = (
                  rec_type +  
                  str(id).zfill(10) +  
                  "{:<40}".format(name)[0:40] + 
                  "{:<40}".format(addr1)[0:40] 
            )
    encoded = bytearray(record.encode('utf-8'))
    out_file.write(encoded)
        

def load_big():
    log("Start")
    c1_df = pd.read_csv(big_dir + '/' + 'C1.csv', sep= ';')
    log("after c1:")
 
    c2_df = pd.read_csv(big_dir + '/' + 'C2.csv', sep= ';')
    log("after c2:")

    c3_df = pd.read_csv(big_dir + '/' + 'C3.csv', sep= ';')
    log("after c3:")
    
    
    c1_c3_df = pd.merge(c1_df, c3_df, on='ID', how='left', indicator = 'merge_result')
    log("after join c1 C3")

    c2_c3_df = pd.merge(c2_df, c3_df, on='ID', how='left', indicator = 'merge_result')
    log("after join c2 c3:")

    c1_c2_ID = pd.concat([pd.DataFrame(c1_c3_df['ID']), pd.DataFrame(c2_c3_df['ID'])])
    c3_only=pd.merge(c3_df, c1_c2_ID, on='ID', how='left', indicator = 'merge_result')
    c3_only=c3_only.loc[c3_only['merge_result'] == 'left_only']
    print(c3_only)

    # create the outfile
    out_file = open(out_dir + '/' + "C1_C3_outfile.txt", "wb")
    for index, row in c1_c3_df.iterrows():
        write_row(out_file,"C1C3", row['ID'], row['NAME'], row['ADDR1'] )

    for index, row in c2_c3_df.iterrows():
        write_row(out_file,"C2C3", row['ID'], row['NAME2'], row['ADDR1'] )

    for index, row in c3_only.iterrows():
        write_row(out_file,"C3  ", row['ID'], "", row['ADDR1'] )

    # End of file - let's close the output file
    out_file.close()

def load_config():
    config_df = pd.read_csv('python/config/my_config.csv', sep = ';')
    return dict(config_df.values)
   
print('current directory:' + os.getcwd())
file_name = 'cust.xlsx'
clear_dir(out_dir)
config = load_config()
big_dir=config["input_dir"]

build_big(int(config["numc1"]), int(config["numc2"]))
load_big()
 
exit(0)
 
# importing the module
import base64
# https://www.dataquest.io/blog/excel-and-pandas/ 
# assigning our sample to a variable
convertsample = "QXNrUHl0aG9uLmNvbSBpcyB0aGUgYmVzdCE="
# converting the base64 code into ascii characters
convertbytes = convertsample.encode("ascii")
# converting into bytes from base64 system
convertedbytes = base64.b64decode(convertbytes)
# decoding the ASCII characters into alphabets
decodedsample = convertedbytes.decode("ascii")
# displaying the result
# print(f"The string after decoding is: {decodedsample}