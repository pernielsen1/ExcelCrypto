#!/bin/bash
#----------------------------------------------------------------------
# deletes topics if already there and creates new with given NUM_PARTIIONS
#-----------------------------------
if [ $# -eq 0 ]
  then
    NUM_PARTITIONS=4
    echo "No arguments supplied defaults to $NUM_CONSUMERS"
else
    NUM_PARTITIONS=$1
fi

# pers-control does not have partitions but a number of consumers listening for stop message
python3 create_topic.py pers-control 1
# pers-topic is where we have the consumers passed as NUM_PARTIOTIONS
python3 create_topic.py pers-topic $NUM_PARTITIONS
