CXX=g++
INCLUDE_DIR=./../include

CXXFLAGS+=-std=c++11 -D_FILE_OFFSET_BITS=64 -Wall -g -O0 -I$(INCLUDE_DIR)

all: analysis

tidy:
	rm -rf *.o
clean:
	rm -rf analysis *.o
# Linker command
analysis: analysis.o
	$(CXX) $(LDFLAGS) -o $@ $^
	$(MAKE) tidy

#Compilation commands
analysis.o: analysis.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $^
