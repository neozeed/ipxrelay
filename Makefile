CC	= gcc
CWARN	= -W -Wall
COPT	= -g -O2
CREQ	=
CFLAGS	= $(CWARN) $(COPT) $(CREQ)
LDFLAGS	=
LIBS	=
X	=
O	= o

.SUFFIXES: .c .$(O) .S .s .i

.c.$(O):
	$(CC) $(CFLAGS) -c -o $@ $<
.c.s:
	$(CC) $(CFLAGS) -S -o $@ $<
.c.i:
	$(CC) $(CFLAGS) -E -o $@ $<
.S.$(O):
	$(CC) $(CFLAGS) -c -o $@ $<
.S.s:
	$(CC) $(CFLAGS) -E -o $@ $<

all: ipxrelay$(X)

ipxrelay$(X): ipxrelay.$(O)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f ipxrelay$(X) *.$(O)

spotless: clean
	rm -f *~ \#*

win32:
	$(MAKE) CC=i686-pc-mingw32-gcc LIBS=-lws2_32 X=.exe O=obj all
