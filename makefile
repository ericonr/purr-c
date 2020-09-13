INC = -Iextern
CFLAGS = -O2 -g -pipe -Wall -Wextra $(INC)
LDLIBS = -lbearssl -lsbearssl -lskarnet
LDFLAGS = -Wl,--as-needed

BASEENCODE = extern/libbaseencode/baseencode.a
LIBS = $(BASEENCODE)

FINAL = purr
OBJS = purr.o socket.o urls.o files.o comm.o formats.o encrypt.o

TEST = tests
TOBJS = tests.o formats.o urls.o

all: $(FINAL)

check: $(TEST)
	./tests

$(OBJS): purr.h
purr: $(OBJS) $(LIBS)
tests: $(TOBJS) $(LIBS)

$(BASEENCODE):
	make -C extern/libbaseencode

clean:
	rm -f $(FINAL) $(OBJS) $(TEST) $(TOBJS)
	make -C extern/libbaseencode clean
