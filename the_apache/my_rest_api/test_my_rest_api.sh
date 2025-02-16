#!/bin/sh
curl -i -H "Content-Type: application/json" -X POST -d '{"number":5}' http://127.0.0.1:8080/getSquare
# UNIX_SOCKET="/var/www/sockets/flaskrest.sock"
# echo $UNIX_SOCKET
# ls $UNIX_SOCKET
# curl -i -H "Content-Type: application/json" -X POST -d '{"number":5}' --unix-socket $UNIX_SOCKET http://127.0.0.1:8080/getSquare
# curl -i -H "Content-Type: application/json" -X POST -d '{"number":5}' --unix-socket $UNIX_SOCKET http://dummy:8080/getSquare
