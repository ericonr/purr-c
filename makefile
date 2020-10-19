PREFIX = /usr/local
bindir = $(DESTDIR)$(PREFIX)/bin

include config.mk

OPT = -O2
WARN = -Wall -Wextra -pedantic
CFLAGS += -std=c99 $(OPT) -g -pipe -Werror=implicit $(DEFS)
LDLIBS += -lbearssl
LDFLAGS += $(CFLAGS) -Wl,--as-needed

PURROBJS = socket.o urls.o files.o comm.o formats.o encrypt.o mmap_file.o
PURROBJS += read_certs.o gemini.o pager.o
LIBSOBJS = $(PURROBJS)

HEADERS = purr.h mmap_file.h read_certs.h gemini.h

FINAL = purr gemi tests
OBJS.purr = purr.o
OBJS.gemi = gemi.o
OBJS.tests = tests.o
OBJS = $(foreach var,$(FINAL),$(OBJS.$(var)))

all: $(FINAL)

check: tests
	./tests

$(OBJS) $(PURROBJS): $(HEADERS) config.mk
$(OBJS) $(PURROBJS): CFLAGS += $(WARN)

$(FINAL): $(OBJS.$@) $(LIBSOBJS)

install: $(FINAL)
	install -Dm755 purr $(bindir)
	ln -sf purr $(bindir)/meow
	ln -sf purr $(bindir)/meowd
	install -m755 gemi $(bindir)

clean:
	rm -f $(FINAL) $(OBJS) $(LIBSOBJS)
