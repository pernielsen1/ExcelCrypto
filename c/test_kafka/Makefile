# Open the makefile perspective in the outer left frame
# then there is a build buttom in top of project outline
# Simple makefile for the kafka consumer and producer
# Ctrl-shift-p - opens command palette
# 
ALL: test_kafka_producer test_kafka_consumer

CC=gcc
CFLAGS=-Wall $(shell pkg-config --cflags glib-2.0 rdkafka)
LDLIBS=$(shell pkg-config --libs glib-2.0 rdkafka)

test_kafka_producer: test_kafka_producer.c
	 $(CC) -o test_kafka_producer test_kafka_producer.c -I. $(CFLAGS) $(LDLIBS)

test_kafka_consumer: test_kafka_consumer.c
	 $(CC) -o test_kafka_consumer test_kafka_consumer.c -I. $(CFLAGS) $(LDLIBS)
