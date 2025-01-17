import pandas as pd
import os
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest/'
#------------------------------------------------------------------------------------------------------------------------
# csv_to_dict: with pandas create dictionary with key values from a csv file - names  key and value column can be passsd
#------------------------------------------------------------------------------------------------------------------------
def csv_to_dict(csv_file,key_column='key', value_column='value'):
    return pd.read_csv(csv_file, delimiter=';').set_index(key_column)[value_column].to_dict()

#--------------------------------------------------------------------------------------------------------------------------
# excel_to_dict: with pandas create dictionary with key values from a csv file - names  key and value column can be passsd
#--------------------------------------------------------------------------------------------------------------------------
def excel_to_dict(excel_file,key_column='key', value_column='value'):
    return pd.read_excel(excel_file).set_index(key_column)[value_column].to_dict()

def dump_dict(dict):
    for key, value in dict.items():
        print(key, value)

if __name__ == "__main__":
    dict = csv_to_dict('test_config_dict.csv','key', 'value')
    dump_dict(dict)
    dict_excel = excel_to_dict(excel_dir + 'test_config.xlsx', 'key', 'value')
    dump_dict(dict_excel)
