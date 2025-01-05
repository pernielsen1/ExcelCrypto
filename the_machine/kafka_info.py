# https://stackoverflow.com/questions/55831931/how-to-get-the-latest-offset-from-each-partition-using-kafka-python
from kafka import KafkaConsumer
from kafka import TopicPartition
def getTopicInfos(consumer, topic: str):
    """
    Get topic's informations like partitions with their last offsets.
    Example of result: {'topic': 'myTopic', 'partitions': ['{"partition": 0, "lastOffset": 47}', '{"partition": 1, "lastOffset": 98}']})

    - Parameters:
      consumer: A Kafka consumer.
      topic: A topic name.

    - Return:
      The topic's informations.
    """
    # Get topic-partition pairs
    # E.g: [TopicPartition(topic='myTopic', partition=0), TopicPartition(topic='myTopic', partition=1)]
    tp = [TopicPartition(topic, partition) for partition in consumer.partitions_for_topic(topic)]

    # Get last offsets
    # E.g: {TopicPartition(topic='myTopic', partition=0): 47, TopicPartition(topic='myTopic', partition=1): 98}
    tplo = consumer.end_offsets(tp)

    # Format partition-lastOffset pairs
    # E.g: ['{"partition": 0, "lastOffset": 47}', '{"partition": 1, "lastOffset": 98}']
    plo = ['{' + f'"partition": {item.partition}, "lastOffset": {tplo.get(item)}' + '}' for item in tplo]

    # Concat topic with partition-lastOffset pairs
    # E.g: {'topic': 'myTopic', 'partitions': ['{"partition": 0, "lastOffset": 47}', '{"partition": 1, "lastOffset": 98}']})
    tplo = {"topic": topic, "partitions": plo}

    # Return the result
    return tplo



#--- here we go
consumer = KafkaConsumer(
    'pers-topic',
    bootstrap_servers=['localhost:9092'],
    auto_offset_reset='earliest',
    enable_auto_commit=True,
    group_id='my-group',
        # value_deserializer=lambda x: loads(x.decode('utf-8'))
)

topic_infos = getTopicInfos(consumer, 'pers-topic')
print(topic_infos)

