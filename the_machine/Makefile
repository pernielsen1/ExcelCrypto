# Open the makefile perspective in the outer left frame
# then there is a build buttom in top of project outline
# Simple makefile for the kafka consumer and producer
# Ctrl-shift-p - opens command palette
# 
ALL: producer consumer

CC=gcc
CFLAGS=-Wall $(shell pkg-config --cflags glib-2.0 rdkafka)
LDLIBS=$(shell pkg-config --libs glib-2.0 rdkafka)

producer: producer.c
	 $(CC) -o producer producer.c -I. $(CFLAGS) $(LDLIBS) -lm

test_kafka_consumer: test_kafka_consumer.c
	 $(CC) -o consumer consumer.c -I. $(CFLAGS)  $(LDLIBS) 
