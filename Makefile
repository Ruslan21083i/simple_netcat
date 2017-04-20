CFLAGS := -Wall -g

all: client server

server: client
	cp $< $@

client: simple_netcat.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -f ./client ./server
