import json
import os
config_dir = 'test_rest/server/'
config_file = 'test_server.json'
config={}
def load_config():
    json_data=""
    with open(config_dir +  config_file, 'r') as file:
        # json_data = file.read().replace('\n', '')
        json_data = file.read()
    config = json.loads(json_data)
    return config
def print_config():
    server_dict=config['server']
    print("Name:" + server_dict['name'])
    print("Description:" + server_dict['desciption'])

# here we go
print('current directory:' + os.getcwd())
config=load_config()
print_config()