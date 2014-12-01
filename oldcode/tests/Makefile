CC=gcc
CFLAGS=-lpthread -ggdb `mysql_config --libs_r --cflags` `pkg-config --libs --cflags glib-2.0` -O2

reconnect.o: reconnect.c
	$(CC) -c -o reconnect.o reconnect.c $(CFLAGS)
reconnect: reconnect.o
	$(CC) -o reconnect reconnect.o $(CFLAGS)
connect_speed.o: connect_speed.c
	$(CC) -c -o connect_speed.o connect_speed.c $(CFLAGS)
connect_speed: connect_speed.o
	$(CC) -o connect_speed connect_speed.o $(CFLAGS)

all: reconnect connect_speed
