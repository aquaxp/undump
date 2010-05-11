CC=gcc 
CFLAGS=-Wall -g

undump: undump.o core.o elfcommon.o program.o

clean:
	rm -f undump undump.o elfcommon.o program.o

