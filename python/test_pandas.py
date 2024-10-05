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


def csv_test(out_dir):
    test_dict =  {'acc': ['A1', 'A2', 'A3'],
            'amount_org':[200.12, 400.23, 600], 
            'dummy_number':[1, 2, 3]}
    df = pd.DataFrame(data=test_dict)

    print(df.dtypes)
    outfile=out_dir + "/test.csv"
    df.to_csv(outfile, index=False, sep=";", decimal=",")
    print(outfile)


def excel_csv_test(file_name, out_dir):
    excel_name=excel_dir + "/" + file_name
    print(excel_name)
    df=pd.read_excel(excel_name, sheet_name='POST')
    print(df.dtypes)
    outfile=out_dir + "/test.csv"
    df.to_csv(outfile, index=False, sep=";", decimal=",")

    print(outfile)

def dump_file(file_name):
    file = open(file_name,"r")
    content = file.read()
    print(content)
    file.close()
    return
 
    return

#-----------------------------------------------------------------------------
# util_pandas_info:  print info of a data frame
#-----------------------------------------------------------------------------
def util_pandas_info(df):
    
    print(df.dtypes)

def strip_zero(row):
    return row['num_as_string'].lstrip('0')

def add_zero(row):
    return row['num_as_string'].zfill(9)

def print_df(msg, df):
    print(msg)
    print(df)
#-----------------------------------------------------------------------------
# test_csv:  load the csv file as all string and let's see what we get
#------------------------------------------------------------------------------
indir = "input"
def test_csv():
    df_in= pd.read_csv(indir + "/" + "csv_input.csv", sep=";", dtype=str)
    util_pandas_info(df_in)
    print("before", df_in)
    df_in['num_as_string'] = df_in.apply(strip_zero, axis=1)
    print("after strip_zero", df_in)
    df_in['num_as_string'] = df_in.apply(add_zero, axis=1)
    print("after add zero", df_in)
    df_in['num_as_string'] = df_in['num_as_string'].apply(lambda x: x.lstrip('0'))   
    print("after lambda remove", df_in) 
    df_in['num_as_string'] = df_in['num_as_string'].apply(lambda x: x.zfill(9))   
    print("after lambda add", df_in) 
#
# here we go
print('current directory:' + os.getcwd())
test_csv()
