CFLAGS = -O2 -g -pipe -Wall -Wextra
LDLIBS = -lbearssl -lsbearssl -lskarnet

FINAL = purr

all: $(FINAL)

clean:
	rm -f $(FINAL)
