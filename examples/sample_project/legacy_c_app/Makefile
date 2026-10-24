CC = gcc
CFLAGS = -Wall -O2
LIBS = -lcurl -lsqlite3 -lz -lm -lpthread

app: main.o
	$(CC) -o app main.o $(LIBS)
