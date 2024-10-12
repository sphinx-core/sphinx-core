CC=gcc
OPT=-funroll-loops

# Specify object files
SHA3_OBJS=SHA3.o SWIFFTX.o

# Default target
all: sha3 swifftx

# Compile the main SHA3 executable
sha3: Tester.c $(SHA3_OBJS)
	${CC} -O3 -DSYS_STDINT ${OPT} -msse2 $(SHA3_OBJS) Tester.c -o sha3

# Compile the Go program linking with the C object files
swifftx:
	@if [ -f swifftx.go ]; then \
		go build -o swifftx swifftx.go; \
	else \
		echo "swifftx.go not found!"; \
		exit 1; \
	fi

# Compile C files to object files
%.o: %.c
	${CC} -c $< -o $@

# Debug version
sha3-dbg: Tester.c $(SHA3_OBJS)
	${CC} -g -lm -DSYS_STDINT $(SHA3_OBJS) Tester.c -o sha3-dbg

# Clean up
clean: 
	rm -f *.o *.s *~ sha3 sha3-dbg swifftx
