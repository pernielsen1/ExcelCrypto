import os
import sys
import json
from flask import Flask
app = Flask(__name__)
from app import routes


config_dir = ''
config_file = 'test_server.json'
def load_config():
    json_data=""
    with open(config_dir +  config_file, 'r') as file:
        json_data = file.read()
        # json_data = file.read().replace('\n', '')
    app.cfg = json.loads(json_data)

def print_config(cfg):
    server_dict=cfg['server']
    print("Name:" + server_dict['name'], file=sys.stderr)
    print("Description:" + server_dict['desciption'])

# here we go
print('current directory:' + os.getcwd())
# ties the loaded config to the app object
load_config()
print_config(app.cfg)
print('In __init__.py now', file=sys.stderr)
