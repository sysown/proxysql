PROXYSQL_PATH=../..
PROXYSQL_IDIR=$(PROXYSQL_PATH)/include

CC = afl-g++-fast
CFLAGS = -Wall -fpermissive -pthread
OBJS = c_tokenizer.o

all: afl_test

afl_test: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -I$(PROXYSQL_IDIR) afl_mysql_query_digest.cpp -o afl_test

c_tokenizer.o: c_tokenizer.cpp c_tokenizer.h
	$(CC) $(CFLAGS) -c c_tokenizer.cpp

clean:
	rm -f *~ *.o afl_test
