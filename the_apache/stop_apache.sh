#!/bin/bash
sudo service apache2 stop
sudo service my_rest_api stop
sudo pkill -f /home/perni/ExcelCrypto/the_apache/my_rest_api/flaskvenv