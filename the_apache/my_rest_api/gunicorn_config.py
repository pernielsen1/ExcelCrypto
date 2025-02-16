import multiprocessing

# workers = multiprocessing.cpu_count() * 2 + 1
workers = 3
# let the socket file reside inside apache
umask = 511

bind = 'unix:/var/www/sockets/my_rest_api.sock'
# bind = '127.0.0.1:8080'
# umask = 0o007

reload = True

#logging
accesslog = '-'
errorlog = '-'