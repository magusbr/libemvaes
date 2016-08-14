CC=gcc
#to view debug prints (too much)
#CFLAGS=-I. -g -Wall -D__DEBUG__ -DDEBUG -DDEBUG_ITER
CFLAGS=-I. -Wall
LDFLAGS=-lssl -lcrypto -lm
OBJ = aes.o aes_large.o base64.o urandom.o sha256.o rsa.o
DEMO_OBJ = main.o

LIBRARY = libemvaes.a

all: $(LIBRARY) demo clean

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBRARY): $(OBJ)
	$(AR) rcs -o $@ $^

demo: $(DEMO_OBJ)
	$(CC) $(CFLAGS) -L. $(LDFLAGS) -o $@ $< $(LIBRARY)

clean:
	$(RM) *.o
