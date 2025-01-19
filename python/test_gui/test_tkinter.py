import tkinter as tk
import tkinter.ttk as ttk
import pandas as pd
# import string
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest/'
excel_dir=''

#--------------------------------------------------------------------------------------------
# field = the values in the different fields of the GUI
# pd_gui = our dataframe which will be updated with values from fields when "DoIt" is pressed
#--------------------------------------------------------------------------------------------
fields = {}
pd_gui = None

class my_data_button(ttk.Button):
    data_item = None
    def __init__(self, parent, data_item, *args, **kwargs):
        ttk.Button.__init__(self, parent, *args, **kwargs)
#        self.bind("<Enter>", lambda e: string.set(message))
        self.data_item = data_item

#        self.bind("<Leave>", lambda e: string.set(""))
    def set_data(self, data_item):
        self.data_item = data_item
    def get_data(self):
        return self.data_item
    def button1(event):

        widget_id = event.widget.winfo_id()
        print(widget_id)
        print("button 1A")
#       print(get_data())
 
    def button2(self):
        print("button 2A")
        print(self.data_item())

def another_action():
    print("In another action")

# def update_pd_gui():   
#     print("action 1") 

def update_pd_gui():   
    for key, value in fields.items():
       pd_gui.at[key,'value'] = value.get()

    print(pd_gui)


def button1():
    print("button 1")
   
    for key, value in fields.items():
       pd_gui.at[key,'value'] = value.get()

    print(pd_gui)
    print("end of button 1")

def button2(event = None, pd_gui = None):
    print("button 2")

# Perhaps the global variables could be removed 
# https://stackoverflow.com/questions/16074486/python-tkinter-button-callback
def do_gui():
    global fields
    frame = tk.Tk() 
    frame.title("TextBox Input") 
    frame.geometry('400x200') 
    row_no = 0
    buttons = {}
    button_column = 0
    for index, row in pd_gui.iterrows():
        if (row['type'] == 'text'):
            lbl = tk.Label(frame, text = row['desc']) 
            lbl.grid(row = row_no, column = 0, pady = 2)
           
            fields[index] = tk.Entry(frame)
            fields[index].insert(0, row['value'])    # set the infial value of the field
            fields[index].grid(row = row_no, column = 1,  pady = 2)

        if (row['type'] == 'button'):
            buttons[index] = tk.Button(frame, text = row['desc'], command= eval(row['value']))  
            buttons[index].grid(row = row_no, column = button_column, pady = 3)

        # this did not work !   buttons[index] = tk.Button(frame, text = row['desc'], command= lambda: functions[index](pd_gui))
        #    buttons[index] = tk.Button(frame, text = row['desc'], command= functions[index]) 
        #    buttons[index] = tk.Button(frame, text = row['desc'], command= eval(row['value']))  
        #   buttons[index] = my_data_button(frame, pd_gui, text = row['desc'], command = eval(row['value']))
        #   x = eval('my_data_button.' + row['value'])
        #   buttons[index].bind('<Button-1>', x)
        #   print(x)
        #    buttons[index].set_data(pd_gui)
        #    my_pd_gui= buttons[index].get_data()
        #    print(my_pd_gui)
        #    print(row['value'])
        #    print(eval(row['value']))
        #    buttons[index].bind('<Button-1>', lambda effi: eval(row['value'])(pd_gui)) 
           
        row_no = row_no + 1
#    print(functions)
    print(buttons)
    frame.mainloop() 
    
    
if __name__ == "__main__":
    pd_gui = pd.read_excel(excel_dir + 'test_gui.xlsx').set_index('key')
    print(pd_gui)
    do_gui()