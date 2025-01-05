echo "starting consumers"
python3 py_consumer.py consumer1 &
sleep 1
python3 py_consumer.py consumer2 &
sleep 1
python3 py_consumer.py consumer3 &
# sleep 1
# python3 py_consumer.py consumer4 &

echo "consumers started"
