CC = gcc

all: crawled

crawled: crawled.c
	$(CC) -o crawled crawled.c -lssl -lcrypto -lxml2

clean:
	rm -rf ./crawled_pages
