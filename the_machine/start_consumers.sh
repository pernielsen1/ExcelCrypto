#!/bin/bash
if [ $# -eq 0 ]
  then
    NUM_CONSUMERS=4
    echo "No arguments supplied defaults to $NUM_CONSUMERS"
else
    NUM_CONSUMERS=$1
fi
echo "starting $NUM_CONSUMERS consumers"
for (( i=1; i<=$NUM_CONSUMERS; i++))
do 
   CONSUMER="consumer$i"
#   echo "starting $CONSUMER"
   python3 py_consumer.py $CONSUMER &
done
