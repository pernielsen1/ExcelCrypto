import pandas as pd
import os
import shutil
import datetime
indir = "input"
outdir= "output"
def write_csv(df, file_name):
    # for col in df.columns:
    #    if isinstance(df[col].iloc[0], Decimal):
    #        df[col] = df[col].apply(lambda x: round(x, 2))
    df.to_csv(outdir + '/' + file_name + '.csv', sep=';', encoding='utf-8', index=False)

#-----------------------------------------------------------------------------
# util_pandas_info:  print info of a data frame
#-----------------------------------------------------------------------------
def util_pandas_info(df):
    for series_name, series in df.items():
        print(series_name)
        print(series)
    for column in df:
        print(df[column].name)
        if (df[column].dtype == "object"):
            print("It's an object")
            print(type(df[column].dtype).__name__ )
        
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
def load_csv():
    df= pd.read_csv(indir + "/" + "csv_input.csv", sep=";", dtype=str)
    all_keys= pd.read_csv(indir + "/" + "csv_all_keys.csv", sep=";", dtype=str)


    return df, all_keys

#-----------------------------------------------------------------------------
# test_apply: test different kind of applys
#------------------------------------------------------------------------------
from decimal import Decimal, ROUND_HALF_UP

def test_apply(df_in):
    # convert amoudt to decimal field first make , to . then 2 digits precision
    df_in['amount'] = df_in['amount'].apply(lambda x: Decimal(x.replace(',','.')).quantize(Decimal("1.00")))   
    print("before\n", df_in)
    df_in['num_as_string'] = df_in.apply(strip_zero, axis=1)
    print("after strip_zero", df_in)
    df_in['num_as_string'] = df_in.apply(add_zero, axis=1)
    print("after add zero", df_in)
    df_in['num_as_string'] = df_in['num_as_string'].apply(lambda x: x.lstrip('0'))   
    print("after lambda remove", df_in) 
    df_in['num_as_string'] = df_in['num_as_string'].apply(lambda x: x.zfill(9))   
    print("after lambda add", df_in) 


#-----------------------------------------------------------------------------
# test_groupby: test different kind of applys
#------------------------------------------------------------------------------
def test_groupby(df_in):
    # create a copy of df_in since we will change it
    df_new = df_in.copy(deep=True)
    # first convert the amount string to float since we loaded as string float requires nums as 1.23 not 1,23
    # TBD - add decimals example
    # df_new['amount'] = df_new['amount'].apply(lambda x: x.replace(',','.'))
    df_new['amount'] = df_new['amount'].astype(float)
    df_grp = df_new.groupby('num_as_string').agg(
                            num_duplicates= ('key', 'count'),
                            sum_amount= ('amount', 'sum')
                        )
    print(df_grp)
    return df_grp
#-----------------------------------------------------------------------------
# test_merge: test merge (join) 
#------------------------------------------------------------------------------
def test_merge(df_in, df_grp, all_keys):
    df_res = pd.merge(  left=df_in, right=df_grp,
                        how='left',
                        left_on='num_as_string', 
                        right_on='num_as_string',
                        suffixes=('','_r'),
                        indicator=True   
                    )
    # since we now have a _merge field we take it away before adding next data frame.
    df_res = df_res.drop(['_merge'], axis=1)                
    # now set it together with all keys.
    df_res =  pd.merge(  left=all_keys, right=df_res,
                        how='left',
                        left_on='key', 
                        right_on='key',
                        suffixes=('','_r'),
                        indicator=True   
                    )                 
    # the num_as_string now has an entry from the the right which have gotten the name num_as_string_r 
    # and it has a  num_as_string which is something completely different from all_keys rename both
    df_res=df_res.rename(columns={"num_as_string": "all_keys_num_as_string", "num_as_string_r": "num_as_string"})
    # now we have a number of NaN's - not usefull in later processing so clean up example with lambdas... 
    # df_res['num_as_string'] = df_res['num_as_string'].apply(lambda x : f"" if pd.isna(x) else f"{x}")
    # df_res['amount'] = df_res['amount'].apply(lambda x : f"0" if pd.isna(x) else f"{x}")
    # but more efficient is the fillna syntrax below
    df_res[['num_as_string']] = df_res[['num_as_string']].fillna(value="")
    df_res[['num_duplicates', 'sum_amount', 'amount']] = df_res[['num_duplicates','sum_amount', 'amount']].fillna(value=0)
    print(df_res)
    # remove columns right_string and amount
    df_res = df_res.drop(['all_keys_num_as_string', 'amount'], axis=1)
    print(df_res)
    # example of selecting only part i.e. let's take the left only
    left_only=df_res[df_res['_merge'] == 'left_only']
    print(left_only)
    # and make a subset of columns
    df_res = df_res[['key', 'num_as_string', 'num_duplicates']]
    write_csv(df_res, "df_res")
    print(df_res)

#
# here we go
print('current directory:' + os.getcwd())
df_in, all_keys =load_csv()
util_pandas_info(df_in)
test_apply(df_in)  
df_grp=test_groupby(df_in)
test_merge(df_in,  df_grp, all_keys)
util_pandas_info(df_in)
