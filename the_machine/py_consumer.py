# https://towardsdatascience.com/kafka-python-explained-in-10-lines-of-code-800e3e07dad1
# https://stackoverflow.com/questions/55545964/multiprocessing-in-python-handle-multiple-worker-threads
# https://www.digitalocean.com/community/tutorials/python-multiprocessing-example
# https://quarkus.io/blog/kafka-commit-strategies/
# https://www.codeflood.net/blog/2022/04/05/kafka-consumer-not-consuming/
#             outfile_max.flush()
#             outfile_max.flush()
# For anyone who wants solution for newer Kafka versions.Please follow this method.# #
# 
# Kafka's entire data retention and transfer policy depends on partitions so be careful about effects of increasing partitions. (Kafka's newer versions display warning regarding this) Try to avoid configuration in which one broker has too many leader partitions.
#
# There is simple 3 stage approach to this.
# 3
# Step 1: Increase the partitions in topics
# ./bin/kafka-topics.sh --bootstrap-server localhost:9092 --alter --topic testKafka_5 --partitions 6--- 
#
# to get all partitions & consumers active ensure unique keye in message
# https://stackoverflow.com/questions/74900130/kafka-is-not-sending-messages-to-other-partitions

import sys
import time
import threading
from datetime import datetime, timezone
import crypto_client
from kafka import KafkaConsumer
from json import loads
#---------------------------------
# Global vars and constants
#------------------------
ONE_BILLION = 1000000000
NUM_MAX = 5
max_array = []
NUM_MIN = 10
max_count = 0
min_count = 0
first_message= 0
last_message =0 
total_messages = 0
name = ''

#-------------------------------------------------------------------------
# add_max ... updates a max entry in the max_array round robin
#--------------------------------------------------------------------------
def add_max(b_init, new_max_diff, new_max_nano):
    global max_count
    global max_array
    max_count = max_count + 1
    if (max_count == NUM_MAX):
        max_count = 0
    dict = { 'max_diff': new_max_diff, 'new_max_nano': new_max_nano}
    if (b_init):
        max_array.append(dict)
    else:
        max_array[max_count] = dict
#----------------------------------------------------------
# control: wait for message and then exist
#------------------------------------------------------------
def controller():
    print("in control:" + name)
    my_start_time_nanos = str(time.clock_gettime_ns(time.CLOCK_REALTIME))
    
    controller_consumer = KafkaConsumer(
        'pers-control',
        bootstrap_servers=['localhost:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
#        group_id=name,
        value_deserializer=lambda x: loads(x.decode('utf-8'))
    )

    for message in controller_consumer:
        if (message.value['consumer'] == name and my_start_time_nanos < message.value['time_nanos']):
        #    print('Time to exit')
            return         
        # else:
        #    print("not message to me or to old")  


#----------------------------------------------------------
# control: get_time
# ------------------------------------------------------------
def get_time(m_value):
    pos_point = m_value.find(".")
    total_nano = (int(m_value[0:pos_point]) * 1000000000) + int( m_value[pos_point+1:len(m_value)])
    t1 = time.clock_gettime_ns(time.CLOCK_REALTIME) 
    diff = t1 - total_nano
    return t1, total_nano, diff

#-----------------------------------------------------------
# consume i.e. the worker
#------------------------------------------------------------"
def consume():
    global total_messages
    global first_message
    global last_message
    global name
    total_messages = 0
    first_message = 0
    last_message = 0
    
    consumer = KafkaConsumer(
        'pers-topic',
        bootstrap_servers=['localhost:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='my-group',
        # value_deserializer=lambda x: loads(x.decode('utf-8'))
    )
    # partitions = consumer.partitions_for_topic('pers-topic')
    # print("partions:" + str(partitions))
    partitions = consumer.assignment()
    print("Consumer " + name + " has this assignment:")
    print(partitions)
    min_diff = 0
    min_msg_no = 0
    max_diff = 0
    max_msg_no = 0 
    num_msg = 0
    for message in consumer:
        total_messages = total_messages + 1
        crypto_client.run_test()
        m_value = message.value.decode('utf-8')
        t1, total_nano, diff = get_time(m_value)
        if first_message == 0:
            first_message = total_nano
        last_message = total_nano
        num_msg = num_msg + 1
        if (diff > max_diff):
            max_diff = diff
            max_diff_sec = max_diff / 1000000000
            max_msg_no = num_msg
            add_max(False, diff, total_nano)

        if (diff < min_diff or min_diff ==0):
            min_diff = diff
            min_diff_sec = min_diff / 1000000000
            min_msg_no = num_msg

#---------------------------------------------------------------------------------------------
# get_timestamp(time_nano)  - create an iso timestamp based on the nano seconds timestam
#----------------------------------------------------------------------------------------------
def get_timestamp(time_nano):
    seconds = time_nano / ONE_BILLION
    dt_obj = datetime.fromtimestamp(seconds)
    return dt_obj.isoformat()
#--------------------------------------
# - here we go - the main thing
#---------------------------------------
name = sys.argv[1]

print("starting at:" + get_timestamp(time.clock_gettime_ns(time.CLOCK_REALTIME)))

crypto_client.crypto_client_init()
crypto_client.run_test()
# outfile_max =open("log/" + name + "_max.log", "w")
# outfile_min =open("log/" + name + "_min.log", "w")
for i in range(NUM_MAX):
    add_max(True, 0, 0)
# consumer_thread = threading.Thread(target=lambda: consume(outfile_max, outfile_min))
consumer_thread = threading.Thread(target=lambda: consume())
consumer_thread.daemon = True
consumer_thread.start()
controller()

first_message_time = get_timestamp(first_message)
last_message_time = get_timestamp(last_message)
total_run_time = last_message - first_message
total_run_time_sec = total_run_time / ONE_BILLION
result = ("NumMessages:" + str(total_messages) + 
        " handled in:" + str(total_run_time_sec) + 
        " start:" + first_message_time  + " end:" + last_message_time + "\n"
        )
# print(max_array)
for max_ent in max_array:
    res = "max_diff as seconds:" + str(max_ent['max_diff'] / ONE_BILLION) + ' at:' + get_timestamp(max_ent['new_max_nano'])
    print(res)

print("Summary:" + result)
# since the consumer_thread is deamon it will die when program dies