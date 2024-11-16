#!/bin/bash
echo starting server
export FLASK_APP=the_server.py
export FLASK_ENV=development
flask run
