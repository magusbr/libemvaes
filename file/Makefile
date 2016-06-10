CC=gcc
#to view debug prints (too much)
#CFLAGS=-I. -D__DEBUG__ -DDEBUG -DDEBUG_ITER
CFLAGS=-I. -Wall
LDFLAGS=-lssl -lcrypto
OBJ = base64.o main2.o

all: main clean

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

main: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	$(RM) *.o
