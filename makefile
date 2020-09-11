CFLAGS = -O2 -g -pipe -Wall -Wextra
LDLIBS = -lbearssl -lsbearssl -lskarnet

FINAL = purr
OBJS = purr.o socket.o urls.o files.o comm.o formats.o

all: $(FINAL)

purr: $(OBJS)

$(OBJS): purr.h

clean:
	rm -f $(FINAL) $(OBJS)
