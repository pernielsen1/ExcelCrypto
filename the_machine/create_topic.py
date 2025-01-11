# https://github.com/confluentinc/confluent-kafka-python/blob/master/examples/adminapi.py
import sys
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.admin.new_partitions import NewPartitions

def add_topic(): 
    admin_client = KafkaAdminClient(
        bootstrap_servers="localhost:9092", 
        client_id='test'
    )

#-----------------------------
# maio
#-----------------------------
if __name__ == '__main__':
    topic_name = sys.argv[1]
    num_part = int(sys.argv[2])
    print("preparing to add/edit" + topic_name + " partiotions:" + str(num_part))
    # exit(0)
    admin_client = KafkaAdminClient(
        bootstrap_servers="localhost:9092", 
        client_id='test'
    )
    topic_exists = False
    topic_list = admin_client.list_topics()
    print(topic_list)
    for topic in topic_list:
        if (str(topic) == topic_name):
            topic_exists = True
    if (topic_exists):
        print("topic exists and will be deleted:" + topic_name + " setting number of partions to " + str(num_part))
        topics_to_delete = [ topic_name]
        admin_client.delete_topics(topics_to_delete)
#        rsp = admin_client.create_partitions({
#            topic_name: NewPartitions(4)
#        })
#        print(rsp)
#        print("partions changed")
    else:   
        print("topic does not exist:" + topic_name)
    if (num_part == 0):
        print("no topci will be created")
    else:
        topic_list_to_add = []
        topic_list_to_add.append(NewTopic(name=topic_name, num_partitions=num_part, replication_factor=1))
        admin_client.create_topics(new_topics=topic_list_to_add, validate_only=False)
        print("topic added")