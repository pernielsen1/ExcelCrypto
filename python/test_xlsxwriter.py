#----------------------------------------------------------------------------------------------
# ToDo: `
#---------------------------------------------------------------------------------------------
import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

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
    format = workbook.add_format()
    format.set_bg_color('yellow')
    worksheet.write("A1", "Hello world")
    row_no=2
    for index, row in df.iterrows():
      for col in df.columns:
          row_no=row_no + 1
          worksheet.write("C" + str(row_no), col)
          worksheet.write("D" + str(row_no), str(row[col]))
          worksheet.write("D" + str(row_no), "Action", format)
          
      # make some space between cases
      row_no=row_no + 1

    # all done
    workbook.close()
   
#----------------------------------------------------------
# apply formula for a number of rows
#--------------------------------------------------------
def apply_formula(ws, formula, column, start_row, num_rows, col_format):
    for row_no in range(num_rows):
       new_formula = formula.replace("#",str(start_row + row_no + 1))
       ws.write_formula(start_row + row_no, column, "=" + new_formula)

    ws.set_column(column, column, 15, col_format)

#----------------------------------------------------------
# dataframe_to_sheet 
#--------------------------------------------------------
def dataframe_to_sheet(df, wb, sheet_name, col_format):
  ws = wb.add_worksheet(sheet_name)
  # write column headings in first rowdata number 0
  col_widths = {}
  cur_col = 0 
  column_names = df.columns
  for col in column_names:
      ws.write(0, cur_col, col)
      col_widths[cur_col] = len(str(col).strip())
      cur_col = cur_col + 1 

  # loop through dataframe row by row and column by column write to cell in Excel
  cur_row = 1  # start after the header row     
  for index, row in df.iterrows():
      cur_col = 0 
      for key, value in row.items():
        if len(str(value).strip()) > col_widths[cur_col] and len(str(value).strip()) < 15:
           col_widths[cur_col] = len(str(value))
        ws.write(cur_row, cur_col, value)
        cur_col  = cur_col + 1
      cur_row = cur_row + 1  
  # create range
  last_cell = xl_rowcol_to_cell(cur_row - 1, cur_col - 1, True, True)
  wb.define_name("Range_" + ws.get_name(), "=" + ws.get_name() + "!" + "$A$2:"  + last_cell)
  # set column widths + apply format with wrap text
  cur_col = 0
  for col in column_names:
    ws.set_column(cur_col, cur_col, col_widths[cur_col] + 2, col_format)
    cur_col = cur_col + 1 

#---------------------
# set_tab_color
#------------------------------
def set_tab_cölor(wb, sheet_name, color):
  ws = wb.get_worksheet_by_name(sheet_name)
  ws.set_tab_color(color)

#----------------------------------------------------------------
# pandas to Excel
#----------------------------------------------------------------
def pandas_to_excel():
  t1 = pd.DataFrame(
    {
      "key": ["k1", "k2", "k3"],
	    "desc": ["Keyval 1 from t1", "Keyval 2 from t1", "keyval 3 from t1"], 
	    "num": [ 1.0, 2.1, 3]
    }
  )
  t2 = pd.DataFrame(
    {
      "key": ["k1", "k2", "k3"],
	    "desc": ["Keyval 1 from t2", "Keyval 2 from t2", "keyval 3 from t2"], 
	    "key_to_t1": [ "k1", "k3", "K2"]
    }
  )
  t3 = pd.DataFrame(
    {
      "key": [],
	    "desc": [], 
    }
  )
  
  out_Excel = excel_dir + "/pandas_to_excel.xlsx"
  wb = xlsxwriter.Workbook(out_Excel)
  col_format = wb.add_format({'text_wrap': True})

  dataframe_to_sheet(t1, wb, "t1", col_format)     
  dataframe_to_sheet(t2, wb, "t2", col_format)     
  dataframe_to_sheet(t3, wb, "t3", col_format)     

  ws_t2 = wb.get_worksheet_by_name("t2")
  formula="VLOOKUP(C#,Range_t1,2,FALSE)"
  apply_formula(ws_t2, formula,3,1,len(t2), col_format)
  set_tab_cölor(wb,'t1','red')
  wb.close()

#--------------------------
# here we go
#--------------------------
pandas_to_excel()
# readExcelAndCreateExcel()
