import pandas as pd
import os
import shutil

excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest'
out_dir='/home/perni/ExcelCrypto/python/output'
# -------------------------------------------------------------------------------
# write a CSV file for each occurence of break field i.e. balance date normally
# -------------------------------------------------------------------------------
def eject_csv(df, break_field, file_name):
    to_df=df.copy(deep=False)
    to_df.drop(to_df.index, inplace=True) # remove all rows keep columns
    first = True
    for index, row in df.iterrows():
        cur_value=row[break_field] 
        if (first):
            break_value=cur_value
            first=False
        if (cur_value != break_value):
            write_csv2(break_value, file_name, to_df)
            break_value = cur_value
            to_df.drop(to_df.index, inplace=True) # remove all rows keep columns
        to_df.loc[len(to_df)]=row    # copy current row      
    if (len(to_df) > 0 ):  # Eject last if not empty
       write_csv2(break_value, file_name, to_df)      

# ----------------------------------------------------------------------------------------------------------------------------
# read all transaction which is sorted in date order - update account balance - when date breaks eject total balance and clear
# ---------------------------------------------------------------------------------------------------------------------------- 
def load_post(file_name):
    df = pd.read_excel(excel_dir + '/' + file_name, sheet_name='POST', index_col=1)
    print(df)

    # Create POST06 & POST07 from transactions
    post06_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID','POTP', 'AMOUNT_GL', 'CUR_GL'])
    post07_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID','POTP', 'ACCOUNT_GL','AMOUNT_GL', 'CUR_GL'])
    for index, row in df.iterrows():
        post06_df.loc[len(post06_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['AMOUNT_GL'], row['CUR_GL']]
        post07_df.loc[len(post07_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['ACCOUNT_GL1'], row['AMOUNT_GL'], row['CUR_GL']]
        post07_df.loc[len(post07_df)] = [row['BAL_DATE'],  row['ACCOUNT_ID'], row['POTP'], row['ACCOUNT_GL2'], -row['AMOUNT_GL'], row['CUR_GL']]
  
    # create summarized SAPGL01 from POST
    SAPGL01_df = post07_df.groupby(['BAL_DATE', 'ACCOUNT_GL', 'CUR_GL'], as_index=False)['AMOUNT_GL'].sum()
 
    # create invoice summary
    advi01_df = df.groupby(['INVOICE_DATE', 'ACCOUNT_ID', 'CUR_GL','INVOICE_NO'], as_index=False)['AMOUNT_GL'].sum()
    advi01_df['OPENBAL'] = advi01_df['AMOUNT_GL']
    advi01_df=advi01_df.set_index('INVOICE_NO', drop=False)
    advi01_chg_df = advi01_df
    print(advi01_df)
 
    # create a summary data set holding balance per account the amount_gl is just dummy field - only really need the keys and a balance field
    sum_pr_account = df.groupby(['ACCOUNT_ID', 'CUR_GL'], as_index=False)['AMOUNT_GL'].sum()
    sum_pr_account['BALANCE'] = 0
    sum_pr_account=sum_pr_account.set_index('ACCOUNT_ID', drop=False)
    ARAC03_df= pd.DataFrame(columns=['BAL_DATE','ACCOUNT_ID','BAL_TYPE', 'AMOUNT_GL', 'CUR_GL'])
    for i in range(len(df)):
        cur_account=df.loc[df.index[i], 'ACCOUNT_ID']
        sum_pr_account.at[cur_account,'BALANCE'] = sum_pr_account.loc[cur_account, 'BALANCE'] + df.loc[df.index[i], 'AMOUNT_GL']
        cur_bal_date= df.loc[df.index[i], 'BAL_DATE']    
        # peek at next row if end of data set or new BAL_DATE then time to write balances
        if ((i+1)==len(df) or (cur_bal_date != df.loc[df.index[i+1], 'BAL_DATE'])):
            for index, row in sum_pr_account.iterrows():
                ARAC03_df.loc[len(ARAC03_df)] = [cur_bal_date,  row['ACCOUNT_ID'], 1, row['BALANCE'], row['CUR_GL']]

    # write to csv
    eject_csv(post06_df, 'BAL_DATE', 'POST06')
    eject_csv(post07_df, 'BAL_DATE', 'POST07')
    eject_csv(ARAC03_df, 'BAL_DATE', 'ARAC03')
    eject_csv(SAPGL01_df, 'BAL_DATE', 'SAPGL01')

    # end of post
                
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
# to_df.reset_index(drop=True, inplace=True)
 
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