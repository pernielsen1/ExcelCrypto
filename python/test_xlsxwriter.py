#----------------------------------------------------------------------------------------------
# https://dev.mysql.com/doc/connector-python/en/connector-python-example-cursor-select.html
#---------------------------------------------------------------------------------------------
import xlsxwriter
import pandas as pd
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest'

from datetime import datetime, timedelta
def readExcelAndCreateExcel():
    in_Excel = excel_dir + "/InputExcel.xlsx"
    out_Excel = excel_dir + "/OutputExcel.xlsx"
    df = pd.read_excel(in_Excel)
    print(df)
    workbook = xlsxwriter.Workbook(out_Excel)
    worksheet = workbook.add_worksheet()
    worksheet.write("A1", "Hello world")
    row_no=2
    for index, row in df.iterrows():
      for col in df.columns:
          row_no=row_no + 1
          worksheet.write("C" + str(row_no), col)
          worksheet.write("D" + str(row_no), str(row[col]))
      # make some space between cases
      row_no=row_no + 1

    # all done
    workbook.close()


#--------------------------
# here we go
#--------------------------

readExcelAndCreateExcel()
