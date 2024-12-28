echo "stopping kafka"
$KAFKA_HOME/bin/kafka-server-stop.sh $KAFKA_HOME/config/server.properties
sleep 1
echo "stopping zookeper"
$KAFKA_HOME/bin/zookeeper-server-stop.sh $KAFKA_HOME/config/zookeeper.properties
echo "all done"