import pandas as pd
import os
import shutil

excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest'
out_dir='/home/perni/ExcelCrypto/python/output'

def eject_csv(df, break_field, file_name):
    first = True
    for index, row in df.iterrows():
        cur_value=row(break_field) 
        if (first):
            break_value=cur_value
        if (cur_value != break_value):
            write_csv2(break_field, file_name, df)
                   



# read all transaction which is sorted in date order - update account balance - when date breaks eject total balance and clear 
def load_post(file_name):
    df = pd.read_excel(excel_dir + '/' + file_name, sheet_name='POST', index_col=1)
    # Create POST06 & POST07 from transactions
    post06_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID','POTP', 'AMOUNT_GL', 'CUR_GL'])
    post07_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID','POTP', 'ACCOUNT_GL','AMOUNT_GL', 'CUR_GL'])
    break_bal_date=0
    for index, row in df.iterrows():
        cur_bal_date=row['BAL_DATE']
        if (cur_bal_date != break_bal_date):
            if (break_bal_date != 0): 
                write_csv2(break_bal_date, 'POST06', post06_df)
                write_csv2(break_bal_date, 'POST07', post07_df)
                post06_df.drop(post06_df.index, inplace=True) # remove all rows keep columns
                post07_df.drop(post07_df.index, inplace=True) # remove all rows keep columns
        # detai handling
      
        break_bal_date=cur_bal_date
        post06_df.loc[len(post06_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['AMOUNT_GL'], row['CUR_GL']]
        post07_df.loc[len(post07_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['ACCOUNT_GL1'], row['AMOUNT_GL'], row['CUR_GL']]
        post07_df.loc[len(post07_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['ACCOUNT_GL2'], -row['AMOUNT_GL'], row['CUR_GL']]
   
    # 
    if (break_bal_date != 0): 
        write_csv2(break_bal_date, 'POST06', post06_df)
        write_csv2(break_bal_date, 'POST07', post07_df)
    # BAL_DATE	TRANS_ID	POTP	ACCOUNT_ID	AMOUNT_TRANS	CUR_TRANS	AMOUNT_GL	CUR_GL	ACCOUNT_GL1	ACCOUNT_GL2	INVOICE_NO	PAYMENT_REF	INVOICE_DATE
    print(df)
    invoice_df = df.groupby(['INVOICE_DATE', 'ACCOUNT_ID', 'CUR_GL','INVOICE_NO'], as_index=False)['AMOUNT_GL'].sum()
    print(invoice_df)   


    sum_df = df.groupby(['BAL_DATE','ACCOUNT_ID','CUR_GL'], as_index=False)['AMOUNT_GL'].sum()
    to_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID', 'AMOUNT_GL', 'CUR_GL'])
    # to_df.reset_index(drop=True, inplace=True)
    for index, row in sum_df.iterrows():
        cur_bal_date=row['BAL_DATE']
        if (cur_bal_date != break_bal_date):
            if (break_bal_date != 0): 
                write_csv2(break_bal_date, 'ARAC03', to_df)
                to_df.drop(to_df.index, inplace=True) # remove all rows keep columns
        # detail handling
        break_bal_date=cur_bal_date
        to_df.loc[len(to_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['AMOUNT_GL'], row['CUR_GL']]
    # end of loop - write last data set
    if(break_bal_date !=0):
        write_csv2(break_bal_date, 'ARAC03', to_df)
    
def write_csv2(bal_date, file_name, df):
    new_dir = out_dir + '/' + str(bal_date)
    if not os.path.isdir(new_dir):
        os.mkdir(new_dir)
    df.to_csv(new_dir + '/' + file_name + '.csv', sep=';', encoding='utf-8', index=False)


                                    
def show_excel(file_name, file_def):
    excel_file= excel_dir + '/' + file_name
    df = pd.read_excel(excel_file, sheet_name="CUST01", index_col=1)
    break_bal_date=''
    df['BAL_DATE2'] = df['BAL_DATE2'].apply(str)
    for index, row in df.iterrows():
        cur_bal_date=row['BAL_DATE2']
        if (cur_bal_date != break_bal_date):
            if (break_bal_date !=''):
                write_csv(new_dir, file_def, to_df)
            # create new empty data set
            to_df= pd.DataFrame(columns=['CUST_ID', 'DELTA2'])
            # create new output dir
            new_dir=out_dir + '/' + cur_bal_date
            os.mkdir(new_dir)
            # store break value
            break_bal_date=cur_bal_date 
        # add the contents of row to the end of to_df
        # https://stackoverflow.com/questions/23549231/check-if-a-value-exists-in-pandas-dataframe-index
        new_index = to_df.index.max() + 1
        to_df.loc[new_index] = [row["CUST_ID"], row["DELTA"]]
    # Write the last file - if there was any
    if (break_bal_date !=''):
       write_csv(new_dir, file_def, to_df)
       
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
    

print('current directory:' + os.getcwd())

file_name = 'cust.xlsx'
clear_dir(out_dir)
# show_excel(file_name, 'CUST01')
load_post(file_name)
exit(0)
excel_file= file_dir + '/' + file_name
print(excel_file)
movies = pd.read_excel(excel_file)
movies_sheet1 = pd.read_excel(excel_file, sheet_name=0, index_col=0)
movies_sheet1.head()
print(movies_sheet1)
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