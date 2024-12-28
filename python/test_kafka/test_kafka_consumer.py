# https://towardsdatascience.com/kafka-python-explained-in-10-lines-of-code-800e3e07dad1

from kafka import KafkaConsumer
from json import loads

consumer = KafkaConsumer(
    'pers-topic',
     bootstrap_servers=['localhost:9092'],
     auto_offset_reset='earliest',
     enable_auto_commit=True,
     group_id='my-group',
     # value_deserializer=lambda x: loads(x.decode('utf-8'))
     )

num_msg = 0
for message in consumer:
    m_value = message.value.decode('utf-8')
    m_key=message.key.decode('utf-8')
    num_msg = num_msg + 1
    print('Message number:' + str(num_msg) + ' key:' +  str(m_key) + ' value:' + str(m_value))
