CFLAGS = -O2 -g -pipe -Wall -Wextra
LDLIBS = -lbearssl -lsbearssl -lskarnet

FINAL = purr
OBJS = purr.o socket.o urls.o files.o comm.o formats.o encrypt.o

TEST = tests
TOBJS = tests.o formats.o

all: $(FINAL)

purr: $(OBJS)

check: $(TEST)
	./tests

tests: $(TOBJS)

$(OBJS): purr.h

clean:
	rm -f $(FINAL) $(OBJS)
