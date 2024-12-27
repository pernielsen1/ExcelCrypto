# export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
# export KAFKA_HOME=/opt/kafka_2.13-3.3.1/
$KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties >/tmp/zookeeper.log &
sleep 2
$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties >/tmp/kafka.log &
sleep 10
