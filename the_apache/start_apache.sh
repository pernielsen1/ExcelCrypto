#!/bin/bash
#  start the Gunicorn
echo "starting gunicorn logs in /home/perni/ExcelCrypto/the_apache2/my_rest_api/var/log"
sudo service my_rest_api start
echo "starting apache logs are in: /var/log/apache2"
sudo service apache2 start