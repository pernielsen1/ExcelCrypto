#----------------------------------------------------
# test_kafka:
# install kafka on Ubuntu wsl
# https://medium.com/@vpriyanshu671/java-development-kit-jdk-22-installation-guide-for-wsl-455f34676b45
# https://michaeljohnpena.com/blog/kafka-wsl2/
# 
# This one workded - got them started
# https://kontext.tech/article/1047/install-and-run-kafka-320-on-wsl
# https://medium.com/@giodegas/running-apache-kafka-message-broker-in-a-wsl2-ubuntu-22-04-41c342391ca6
# 
# https://towardsdatascience.com/kafka-python-explained-in-10-lines-of-code-800e3e07dad1
#
# and make my first topic
# $KAFKA_HOME/bin/kafka-topics.sh --create --topic pers-topic --bootstrap-server localhost:9092 
#
# $KAFKA_HOME/bin/kafka-topics.sh --describe --topic pers-topic --bootstrap-server localhost:9092
#
# Now to python
# pip install kafka-python
#---------------------------------------------------

from confluent_kafka import Producer
from time import sleep
from json import dumps
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
                         value_serializer=lambda x: 
                         dumps(x).encode('utf-8'))

for e in range(42):
    print("creating message" + str(e))
    data = {'number' : e}
    producer.send('pers-topic', value=data)
    sleep(5)

