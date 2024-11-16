# test_server.py
# cd test-rest/server
# export FLASK_APP=test_server.py
# export FLASK_ENV=development
hw="Hw none"
def init_app(app):
    print("loading")
    hw = "Hello world from init_aoo"

from flask import Flask, request, jsonify
import json

app = Flask(__name__)
init_app(app)

countries = [
    {"id": 1, "name": "Thailand", "capital": "Bangkok", "area": 513120},
    {"id": 2, "name": "Australia", "capital": "Canberra", "area": 7617930},
    {"id": 3, "name": "Egypt", "capital": "Cairo", "area": 1010408},
]


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
    x['result'] = "Hello World 3"
#    return jsonify(x)
#    return json.dumps(x)
    return hw
#    return "Hello world"

@app.post("/countries")
def add_country():
    if request.is_json:
        country = request.get_json()
        country["id"] = _find_next_id()
        countries.append(country)
        return country, 201
    return {"error": "Request must be JSON"}, 415