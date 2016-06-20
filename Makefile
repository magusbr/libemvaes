CC=gcc
#to view debug prints (too much)
#CFLAGS=-I. -Wall -D__DEBUG__ -DDEBUG -DDEBUG_ITER
CFLAGS=-I. -Wall
LDFLAGS=-lssl -lcrypto -lm
OBJ = aes.o base64.o urandom.o sha256.o
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
