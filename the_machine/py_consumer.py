# https://towardsdatascience.com/kafka-python-explained-in-10-lines-of-code-800e3e07dad1
# https://stackoverflow.com/questions/55545964/multiprocessing-in-python-handle-multiple-worker-threads
# https://www.digitalocean.com/community/tutorials/python-multiprocessing-example
# --- 
import sys 
import time 
from kafka import KafkaConsumer
from json import loads


def consume(name):
    consumer = KafkaConsumer(
        'pers-topic',
        bootstrap_servers=['localhost:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='my-group',
        # value_deserializer=lambda x: loads(x.decode('utf-8'))
        )
    min_diff = 0
    min_msg_no = 0
    max_diff = 0
    max_msg_no = 0 
    num_msg = 0
    for message in consumer:
        m_value = message.value.decode('utf-8')
        m_key=message.key.decode('utf-8')
        num_msg = num_msg + 1
        pos_point = m_value.find(".")
        str_seconds = m_value[0:pos_point]
        str_nano = m_value[pos_point+1:len(m_value)]
        long_seconds = int(str_seconds)
        long_nano = int(str_nano)
        t1 = time.clock_gettime_ns(time.CLOCK_REALTIME) 
        total_nano = long_seconds * 1000000000 + long_nano 
        diff = t1 - total_nano
        if (diff > max_diff):
            max_diff = diff
            max_diff_sec = max_diff / 1000000000
            max_msg_no = num_msg
            print("max_diff:" + str(max_diff) + " found at:" + str(max_msg_no) + " in secs:" + str(max_diff_sec))
        if (diff < min_diff or min_diff ==0):
            min_diff = diff
            min_diff_sec = min_diff / 1000000000
            min_msg_no = num_msg
            print("min_diff:" + str(min_diff) + " found at:" + str(min_msg_no) + " in secs:" + str(max_diff_sec))

    #    print('Message number:' + str(num_msg) + ' key:' +  str(m_key) + ' value:' + str(m_value) + 
    #          " seconds:" + str(long_seconds) + " nano:" + str(long_nano) + " diff:" + str(diff) + 
    #          "Sys:" + str(t1) + " total" + str(total_nano))

# - here we go
name = sys.argv[1]

print("name:" + name)
consume(name)