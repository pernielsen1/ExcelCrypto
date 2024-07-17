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
#   encoded = bytearray(record.encode('cp1143'))
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

def pandas_test():
    acc =  {'acc': ['A1', 'A2', 'A3'],
            'pt': ['P10', 'P20', 'P30']}
    trn =  {'entity':[101, 101, 101], 'acc': ['A1', 'A1', 'A2'], 
          'amount_gc': [100, 200, 300], 'amount_org':[200, 400, 600], 
          'dummy_number':[1, 2, 3]}
    df_trn = pd.DataFrame(data=trn)
    df_acc = pd.DataFrame(data=acc)
    print(df_trn)
    print(df_acc)
    # example of left join i.e. merge in pandas speak
    df_acc_trn =pd.merge(df_acc, df_trn, on='acc', how='left', indicator = 'merge_result')
    print(df_acc_trn)
    # how to select rows
    # https://stackoverflow.com/questions/17071871/how-do-i-select-rows-from-a-dataframe-based-on-column-values
    # select those with value > 100 
    df_acc_trn_gt100 = df_acc_trn.loc[df_acc_trn['amount_gc'] > 100 ]
    # select those with value > 100 and account = A1
    print(df_acc_trn_gt100)

    df_acc_trn_gt100_and_a1 = df_acc_trn.loc[(df_acc_trn['amount_gc'] > 100) & 
                                             (df_acc_trn['acc'] == 'A1') ]

    print(df_acc_trn_gt100_and_a1)
    # example of summarising (group by)
    df_trn_sum = df_trn.groupby(['entity', 'acc']).agg({'amount_gc':'sum','amount_org':'sum'})
    print(df_trn_sum)

def testinv():
    trn =  {'bal_dat': ['2023-11-30', '2023-11-30', '2023-12-01'],
            'ttypc': ['PURC', 'PURC', 'PAY'],
            'amt': [100, 200, -140],
            'inv_dat': ['2023-11-30', '2023-11-30', '2023-12-31'],
            'inv_no': [1, 1, 2],
            'ref_mo': [0, 0, 1]
            }
    df_trn = pd.DataFrame(data=trn)
    print(df_trn)
    return

def csv_test(out_dir):
    test_dict =  {'acc': ['A1', 'A2', 'A3'],
            'amount_org':[200.12, 400.23, 600], 
            'dummy_number':[1, 2, 3]}
    df = pd.DataFrame(data=test_dict)

    print(df.dtypes)
    outfile=out_dir + "/test.csv"
    df.to_csv(outfile, index=False, sep=";", decimal=",")
    print(outfile)

def write_trailer(file_name, num_rows):
    now = datetime.datetime.now()
    str_time=now.strftime('%Y-%m-%dT%H:%M:%S') + ('-%02d' % (now.microsecond / 10000))
    str_trailer="99," + str_time + "," + str(num_rows)
    f1 = open(file_name, "a")  # append mode
    f1.write(str_trailer + "\n")
    f1.close()

def excel_csv_test(file_name, out_dir):
    excel_name=excel_dir + "/" + file_name
    print(excel_name)
    df=pd.read_excel(excel_name, sheet_name='POST')
    print(df.dtypes)
    outfile=out_dir + "/test.csv"
    df.to_csv(outfile, index=False, sep=";", decimal=",")
    write_trailer(outfile, len(df))

    print(outfile)

class out_file:
    
    def __init__(self, segment, outdir, infile):
        self.segment=segment
        self.num_recs=0
        self.num_err_recs = 0
        self.outdir = outdir
        self.infile=infile
        self.fileno=0
        self.open_out_file()
    def open_out_file(self): 
        self.out_file = open(self.outdir + "/" + self.infile + '_' + self.segment + "_" + 
                             str(self.fileno) + "_" + ".txt"
                             , "w", encoding="ISO-8859-2")
    def get_out_file(self):
        return self.out_file
    

def write_line(out_file_dict, txt_line, segment, outdir, infile):
    if not (segment in out_file_dict.keys()):
        out_file_obj = out_file(segment, outdir, infile)
        out_file_dict.update({segment: out_file_obj})
    file_obj = out_file_dict.get(segment)
    file_obj.num_recs = file_obj.num_recs + 1
    file_obj.out_file.write(txt_line) 

def close_files(out_file_dict, out_dir):
    stat_file = open(out_dir + "/stat_out_file_dict.csv", "w")
    for k  in out_file_dict:
        out_file_obj = out_file_dict[k]
        out_file_obj.out_file.close()
        stat_file.write(out_file_obj.segment + ";" + str(out_file_obj.num_recs) 
                        + ";" + str(out_file_obj.num_err_recs) 
                        + "\n")
import csv    
def loadcsv_todict():
    input_dict = csv.DictReader(open("test.csv"), delimiter=";")
    for row in input_dict:
        print(row)
    v = input_dict.get("k1")
    print("value for k1 is"  + v1 )

print('current directory:' + os.getcwd())
# loadcsv_todict()
#file_name = 'cust.xlsx'
clear_dir(out_dir)
f_dict=dict()
write_line(f_dict, "l1" + "\n", "s1", out_dir, "infile")
write_line(f_dict, "l2" + "\n", "s2", out_dir, "infile")
write_line(f_dict, "l3" + "\n", "s1", out_dir, "infile")
write_line(f_dict, "l4" + "\n", "s2", out_dir, "infile")
close_files(f_dict, out_dir)
# # out_file1 = open('f1-txt', 'w')
# out_file2 = open('f2.txt', 'w')
# f_dict.update({"f1": out_file1})
#f_dict.update({"f2": out_file2})
# f=f_dict.get("f1")
# f.write("t1")
# f=f_dict.get("f2")
# f.write("t2")
# out_file1.close()
# out_file2.close()
# this_dict = {
#    "name" : "f1",
#    "f_obj" : out_file1
#}

#excel_csv_test(file_name, out_dir)
# config = load_config()
# big_dir=config["input_dir"]
# testinv()
# build_big(int(config["numc1"]), int(config["numc2"]))
# load_big()
# pandas_test()   
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