# https://stackoverflow.com/questions/52080471/how-to-list-kafka-consumer-group-using-python
# https://gpttutorpro.com/how-to-use-kafka-admin-api-with-python-to-manage-kafka-clusters/
from kafka import KafkaAdminClient
from kafka import BrokerConnection
from kafka.protocol.admin import *
import socket

# bc = BrokerConnection('localhost', 9092, socket.AF_INET)
# bc.connect_blocking()

# list_groups_request = ListGroupsRequest_v1()

# future = bc.send(list_groups_request)
# while not future.is_done:
#    for resp, f in bc.recv():
#        f.success(resp)
# 
# for group in future.value.groups:
#     print(group)

topics_in_groups = {}
client = KafkaAdminClient(bootstrap_servers=['localhost:9092'])

for group in client.list_consumer_groups():
    topics_in_groups[group[0]] = []

for group in topics_in_groups.keys():
    my_topics = []
    topic_dict = client.list_consumer_group_offsets(group)
    for topic in topic_dict:
        my_topics.append(topic.topic)
        topics_in_groups[group] = list(set(my_topics))

for key , value in topics_in_groups.items():
    print(key, "\n\t", value)

# describe_consumer_groups