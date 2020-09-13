INC = -Iextern
OPT = -O2
WARN = -Wall -Wextra
CFLAGS = $(OPT) -g -pipe
LDLIBS = -lbearssl -lsbearssl -lskarnet
LDFLAGS = -Wl,--as-needed

BASEENCODE = extern/libbaseencode/baseencode.a
BASEENCODEOBJS = extern/libbaseencode/base64.o extern/libbaseencode/base32.o
LIBS = $(BASEENCODE)
LIBSOBJS = $(BASEENCODEOBJS)

FINAL = purr
OBJS = purr.o socket.o urls.o files.o comm.o formats.o encrypt.o

TEST = tests
TOBJS = tests.o formats.o urls.o

all: $(FINAL)

check: $(TEST)
	./tests

$(OBJS): purr.h
$(OBJS): CFLAGS += $(WARN) $(INC)
purr: $(OBJS) $(LIBS)
tests: $(TOBJS) $(LIBS)

$(BASEENCODEOBJS): extern/libbaseencode/common.h extern/libbaseencode/baseencode.h
$(BASEENCODE): $(BASEENCODEOBJS)
	$(AR) r $@ $^

clean:
	rm -f $(FINAL) $(OBJS) $(TEST) $(TOBJS) $(LIBS) $(LIBSOBJS)
