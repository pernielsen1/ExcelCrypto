# pers-control does not have partitions but a number of consumers listening for stop message
python3 create_topic.py pers-control 1
# pers-topic is wherre we have the consumers currently 3
python3 create_topic.py pers-topic 3
