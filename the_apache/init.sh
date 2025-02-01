#!/bin/bash
# https://learn.microsoft.com/en-us/windows/python/web-frameworks
# sudo apt install apache2
# https://learn.microsoft.com/en-us/windows/wsl/systemd
# config file: 
# cat /etc/apache2/apache2.conf
python3 -m venv .venv.
source .venv/bin/activate
sudo service apache2 start