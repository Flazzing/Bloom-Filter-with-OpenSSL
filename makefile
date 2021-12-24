INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -g -I$(INC) -L$(LIB) -o enc main.c -lcrypto -ldl
