CC = g++
CPPFLAGS = -std=c++17
LDLIBS = -lpcap 

all: tcp-block

tcp-block: tcp-block.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
