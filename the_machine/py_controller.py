#----------------------------------------------------
# 
# --------------------------------------------------

import time
import sys
from kafka import KafkaProducer
from json import dumps

def stop_consumer(consumer):
    print("stopping consumer" + consumer)
    t1 = time.clock_gettime_ns(time.CLOCK_REALTIME) 
    
    data = {'time_nanos' : str(t1), 
            'consumer': consumer}
    
    producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
                         value_serializer=lambda x: 
                         dumps(x).encode('utf-8'))
    producer.send('pers-control', value=data)   
    producer.flush()                  
    
# here we go
stop_consumer(sys.argv[1])
