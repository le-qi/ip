#You can use either a gcc or g++ compiler
CC = g++
#CC = gcc
EXECUTABLES = main
CFLAGS = -I. -Wall -lm -g
#Disable the -DNDEBUG flag for the printing the freelist
#CFLAGS = -Wall -I.
PTFLAG = -O2
DEBUGFLAG = -g

all: ${EXECUTABLES}

test: CFLAGS += $(OPTFLAG)
test: ${EXECUTABLES}
	for exec in ${EXECUTABLES}; do \
    		./$$exec ; \
	done

debug: CFLAGS += $(DEBUGFLAG)
debug: $(EXECUTABLES)
	for dbg in ${EXECUTABLES}; do \
		gdb ./$$dbg ; \
	done

main: main.cc
	$(CC) $(CFLAGS) -pthread -o main main.cc ipsum.h ipsum.c

clean:
	rm -f *.o ${EXECUTABLES} a.out

