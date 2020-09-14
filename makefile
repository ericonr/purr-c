PREFIX = /usr/local

include config.mk

OPT = -O2
WARN = -Wall -Wextra -Werror=implicit
CFLAGS += $(OPT) -g -pipe $(DEFS)
LDLIBS += -lbearssl
LDFLAGS += -Wl,--as-needed
INC += -Iextern

BASEENCODE = extern/libbaseencode/baseencode.a
BASEENCODEOBJS = extern/libbaseencode/base64.o extern/libbaseencode/base32.o
LIBS = $(BASEENCODE)
LIBSOBJS = $(BASEENCODEOBJS)

FINAL = purr
HEADERS = purr.h mmap_file.h
OBJS = purr.o socket.o urls.o files.o comm.o formats.o encrypt.o mmap_file.o read_certs.o

TEST = tests
TOBJS = tests.o formats.o urls.o mmap_file.o

all: $(FINAL)

check: $(TEST)
	./tests

$(OBJS) $(TOBJS): $(HEADERS) config.mk
$(OBJS) $(TOBJS): CFLAGS += $(WARN)
encrypt.o: CFLAGS += $(INC)

purr: $(OBJS) $(LIBS)
tests: $(TOBJS) $(LIBS)

$(BASEENCODEOBJS): extern/libbaseencode/common.h extern/libbaseencode/baseencode.h
$(BASEENCODE): $(BASEENCODEOBJS)
	$(AR) r $@ $^

install: $(FINAL)
	install -Dm755 purr $(DESTDIR)$(PREFIX)/bin
	ln -sf purr $(DESTDIR)$(PREFIX)/bin/meow
	ln -sf purr $(DESTDIR)$(PREFIX)/bin/meowd

clean:
	rm -f $(FINAL) $(OBJS) $(TEST) $(TOBJS) $(LIBS) $(LIBSOBJS)
