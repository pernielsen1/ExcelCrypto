#!/bin/bash
if [ $# -eq 0 ]
  then
    NUM_CONSUMERS=4
    echo "No arguments supplied defaults to $NUM_CONSUMERS"
else
    NUM_CONSUMERS=$1
fi
for (( i=1; i<=$NUM_CONSUMERS; i++))
do 
   CONSUMER="consumer$i"
   python3 py_controller.py $CONSUMER
done

