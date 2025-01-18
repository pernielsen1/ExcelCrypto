import PySimpleGUI as sg
import pandas as pd
excel_dir='/mnt/c/users/perni/OneDrive/Documents/PythonTest/'
excel_dir=''
def do_gui(pd_gui):
    layout = [  [sg.Text("What's your name?")],
            [sg.InputText()],
            [sg.Button('Ok'), sg.Button('Cancel')] ]
    layout2 = []

    for index, row in pd_gui.iterrows():
        if (row['type'] == 'text'):
            layout2.append([sg.Text(row['desc'])])
            layout2.append([sg.InputText(default_text=row['value'],key=index)])
        if (row['type'] == 'button'):
            layout2.append([sg.Button(row['desc'])])

    window = sg.Window('Hello Example', layout2)

    # Event Loop to process "events" and get the "values" of the inputs
    while True:
        event, return_values = window.read()
        # update the data frame with the value returned from GUI
        for key, value in return_values.items():
           pd_gui.at[key,'value'] = value
     
        print(pd_gui)
        # if user closes window or clicks cancel
        if event == sg.WIN_CLOSED or event == 'Cancel':
            break
        # tbd update the data frame


    window.close()
    
if __name__ == "__main__":
    pd_gui = pd.read_excel(excel_dir + 'test_gui.xlsx').set_index('key')
    print(pd_gui)
    for index, row in pd_gui.iterrows():
        print(index, ' value' +row['value'])

    x1_value = pd_gui.loc['x1']['value']
    print(x1_value)
    do_gui(pd_gui)