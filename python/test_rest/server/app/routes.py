from app import app
import json
from flask import request, jsonify
from flask import current_app
import simulator

countries = [
    {"id": 1, "name": "Thailand", "capital": "Bangkok", "area": 513120},
    {"id": 2, "name": "Australia", "capital": "Canberra", "area": 7617930},
    {"id": 3, "name": "Egypt", "capital": "Cairo", "area": 1010408},
]


@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

#--------------------------------------------------
# transcode_0100 = the request answer with a 0100
#--------------------------------------------------
@app.post("/transcode_0100")
def add_transcode_0100():
    if request.is_json:
        msg_str = request.get_json()
        print(msg_str)
        msg = simulator.build_reply_msg(msg_str)
        return msg, 201
    return {"error": "Request must be JSON"}, 415


def _find_next_id():
    return max(country["id"] for country in countries) + 1

@app.get("/countries")
def get_countries():
    return jsonify(countries)

@app.get("/tests")
def get_tests():
    # a Python object (dict):
    x = {
        "parm1": "John",
        "parm2": "30",
        "result": "New York"
    }
    cfg = current_app.cfg
    server_dict=cfg['server']
   
    x['result'] = "Hello World 3" + server_dict['name']
#    return jsonify(x)
    return json.dumps(x)

@app.post("/countries")
def add_country():
    if request.is_json:
        country = request.get_json()
        country["id"] = _find_next_id()
        countries.append(country)
        return country, 201
    return {"error": "Request must be JSON"}, 415