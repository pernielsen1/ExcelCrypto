#!/bin/sh
### BEGIN INIT INFO
# Provides:          my_rest_api
# Required-Start:    $local_fs $network $named $time $syslog
# Required-Stop:     $local_fs $network $named $time $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       <DESCRIPTION>
# 20250216
### END INIT INFO
# the log will be in my_rest_api/var/log/my rest_api.log
/CUR_USER="$(id -u -n)"
PERNI_HOME="/home/perni"
REST_DIR="$PERNI_HOME/ExcelCrypto/the_apache/my_rest_api/"
cd $REST_DIR
# SCRIPT="flaskvenv/bin/gunicorn  --config gunicorn_config.py wsgi:app"
SCRIPT="flaskvenv/bin/gunicorn  --workers=3 --bind unix:/var/www/sockets/my_rest_api.sock -m 777 wsgi:app"
echo "Executing:" $SCRIPT " in dir:" + $REST_DIR " with user:" $CUR_USER
$SCRIPT

