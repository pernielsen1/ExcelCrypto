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
#
# stats:  12 consumers and producer 3000 250 gives around 0.13 after a few runs seconds average 0,07 
#
# $KAFKA_HOME/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --group my-group --describe

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
NUM_MAX = 3
max_array = []
NUM_MIN = 3
min_array = []
max_count = 0
min_count = 0
first_message= 0
last_message =0 
total_messages = 0
total_diff = 0

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

#-------------------------------------------------------------------------
# add_min ... updates a min entry in the min_array round robin
#--------------------------------------------------------------------------
def add_min(b_init, new_min_diff, new_min_nano):
    global min_count
    global min_array
    min_count = min_count + 1
    if (min_count == NUM_MIN):
        min_count = 0
    dict = { 'min_diff': new_min_diff, 'new_min_nano': new_min_nano}
    if (b_init):
        min_array.append(dict)
    else:
        min_array[min_count] = dict

#----------------------------------------------------------
# control: wait for message and then exist
#------------------------------------------------------------
def controller(name):
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
            return         

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
def consume(name):
    global total_messages
    global first_message
    global last_message
    global total_diff

    total_messages = 0
    first_message = 0
    last_message = 0
    total_diff = 0

    consumer = KafkaConsumer(
        'pers-topic',
        bootstrap_servers=['localhost:9092'],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='my-group',
        # value_deserializer=lambda x: loads(x.decode('utf-8'))
    )
    min_diff = 0
    max_diff = 0
    num_msg = 0
    for message in consumer:
        total_messages = total_messages + 1
        crypto_client.run_test()
        m_value = message.value.decode('utf-8')
        t1, total_nano, diff = get_time(m_value)
        total_diff = total_diff + diff
        if first_message == 0:
            first_message = total_nano
        last_message = total_nano
        num_msg = num_msg + 1
        if (diff > max_diff):
            max_diff = diff
            add_max(False, diff, total_nano)

        if (diff < min_diff or min_diff ==0):
            min_diff = diff
            add_min(False, diff, total_nano)

#---------------------------------------------------------------------------------------------
# get_timestamp(time_nano)  - create an iso timestamp based on the nano seconds timestam
#----------------------------------------------------------------------------------------------
def get_timestamp(time_nano):
    seconds = time_nano / ONE_BILLION
    dt_obj = datetime.fromtimestamp(seconds)
    return dt_obj.isoformat()
#-------------------------------------------------------------------
# - here we go - the consumer name is passed as first parameter
#-------------------------------------------------------------------
name = sys.argv[1]

crypto_client.crypto_client_init()
# initialize min_array and max_arrays
for i in range(NUM_MAX):
    add_max(True, 0, 0)
for i in range(NUM_MIN):
    add_min(True, 0, 0)

# Start the worker consumer_thread 
consumer_thread = threading.Thread(target=lambda: consume(name))
consumer_thread.daemon = True  # will enable the thread to die when we exit mail program
consumer_thread.start()
# start the controller which basically waits for a message to stop.
controller(name)   

total_run_time_sec = (last_message - first_message) / ONE_BILLION
if total_messages > 0:
    average_diff = str((total_diff/total_messages)/ONE_BILLION)
else:
    average_diff = "N/A"
result = ("NumMsg:" + str(total_messages) + 
        " TotalTime:" + str(total_run_time_sec) + 
        " start:" + get_timestamp(first_message)  + " end:" + get_timestamp(last_message) +  
        " average_diff:" + average_diff + "\n"
        )
for max_ent in max_array:
    res = "max_diff as seconds:" + str(max_ent['max_diff'] / ONE_BILLION) + ' at:' + get_timestamp(max_ent['new_max_nano'])
    print(res)

# for min_ent in min_array:
#    res = "min_diff as seconds:" + str(min_ent['min_diff'] / ONE_BILLION) + ' at:' + get_timestamp(min_ent['new_min_nano'])
#    print(res)

print("Summary for:" + name + result)
# since the consumer_thread is deamon it will die when program dies