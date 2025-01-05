import sys
from kafka.admin import KafkaAdminClient, NewTopic

def add_topic(): 
    admin_client = KafkaAdminClient(
        bootstrap_servers="localhost:9092", 
        client_id='test'
    )

#-----------------------------
# maio
#-----------------------------
if __name__ == '__main__':
    name = sys.argv[1]
    num_part = int(sys.argv[2])
    print("preparing to add:" + name + " partiotions:" + str(num_part))
    # exit(0)
    admin_client = KafkaAdminClient(
        bootstrap_servers="localhost:9092", 
        client_id='test'
    )
    topic_list = []

    topic_list.append(NewTopic(name=name, num_partitions=num_part, replication_factor=1))
    admin_client.create_topics(new_topics=topic_list, validate_only=False)