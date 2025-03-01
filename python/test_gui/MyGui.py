# failed to get tkinter to work in wsl "not possible to open display:0" to be continued
from datetime import datetime
import tkinter as tk
import tkinter.ttk as ttk
import pandas as pd
import time
# import string
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest/'
excel_dir=''

#--------------------------------------------------------------------------------------------
# field = the values in the different fields of the GUI
# pd_gui = our dataframe which will be updated with values from fields when "DoIt" is pressed
#--------------------------------------------------------------------------------------------
class MyGui:
    fields = {}
    pd_gui = None
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)
    def __init__(self, callback_button1, callback_button2):
        self.callback_button1 = callback_button1
        self.callback_button2 = callback_button2
        
        self.pd_gui = pd.read_excel(excel_dir + 'test_gui.xlsx').set_index('key')
        self.do_gui()

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

#-------------------------------------------------
# click on buttons
#-------------------------------------------------
    def update_pd_gui(self):   
        for key, value in self.fields.items():
            if (key != 'log'):
                self.pd_gui.at[key,'value'] = value.get()
        print(self.pd_gui)
#-------------------------------------------------
# click on buttons
#-------------------------------------------------
    def button1(self):
        print("button 1")
        self.update_pd_gui()
        self.callback_button1(self.log_message)

    def button2(self):
        print("button 2")
        self.update_pd_gui()
        self.callback_button2(self.log_message)

    def do_gui(self):
        frame = tk.Tk() 
        frame.title("TextBox Input") 
        frame.geometry('400x200') 
        print(self.pd_gui)
        row_no = 0
        buttons = {}
        button_column = 0
        for index, row in self.pd_gui.iterrows():
            if (row['type'] == 'Entry'):
                lbl = tk.Label(frame, text = row['desc']) 
                lbl.grid(row = row_no, column = 0, pady = 2)
            
                self.fields[index] = tk.Entry(frame)
                self.fields[index].insert(0, row['value'])    # set the infial value of the field
                self.fields[index].grid(row = row_no, column = 1,  pady = 2)

            if (row['type'] == 'Text'):
                self.fields[index] = tk.Text(frame, height = 5, width = 30)
                self.fields[index].insert('1.0', 'First message') 
                self.fields[index].grid(row = row_no, column = 1,  pady = 2)


            if (row['type'] == 'Button'):
                buttons[index] = tk.Button(frame, text = row['desc'], command= eval('self.' + row['value']))  
                buttons[index].grid(row = row_no, column = button_column, pady = 3)
            row_no = row_no + 1

        frame.mainloop() 
    
    def log_message(self, message):
        hhmmss = datetime.strftime(datetime.now(), '%H:%M:%S ')

        self.fields['log'].insert('1.0', hhmmss + message + '\n')
        self.fields['log'].update_idletasks()


def my_button1(log_message):
    log_message("start my button 1")
    time.sleep(10)
    log_message("end my button 1")

def my_button2(log_message):
    log_message("start my button 2")

if __name__ == "__main__":


    my_gui = MyGui(my_button1, my_button2)
