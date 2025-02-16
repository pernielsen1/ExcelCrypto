#!/bin/bash
# https://learn.microsoft.com/en-us/windows/python/web-frameworks
# sudo apt install apache2
# https://learn.microsoft.com/en-us/windows/wsl/systemd
# config file: 
# cat /etc/apache2/apache2.conf
# the howto i followed
# sudo pkill -f /home/perni/ExcelCrypto/the_apache/my_rest_api/flaskvenv
# ps -aux
# https://medium.com/@thishantha17/build-a-simple-python-rest-api-with-apache2-gunicorn-and-flask-on-ubuntu-18-04-c9d47639139b
mkdir my_rest_api
cd my_rest_api
python3 -m venv flaskvenv
source flaskvenv/bin/activate
pip install flask
pip install gunicorn
# copy the startup script
chmod +x my_rest_api 
cp my_rest_api /etc/init.d/
cp my_rest_api.conf /etc/apache2/sites-available
cp patch_apache/ports.conf /etc/apache2
# 
ln -sf /etc/apache2/sites-available/my_rest_api.conf /etc/apache2/sites-enabled/

# Enable the proxy modules 
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_balancer
sudo a2enmod lbmethod_byrequests

# might be possible to go through a tmp thing instead... but for now OK
sudo mkdir /var/www/sockets
sudo chown www-data:www-data /var/www/sockets
sudo adduser perni www-data
sudo chmod +777 /var/www/sockets

cd .. 



#--- 
# old 
# python3 -m venv .venv.
# source .venv/bin/activate
# sudo service apache2 start