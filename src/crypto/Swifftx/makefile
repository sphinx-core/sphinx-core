CC = gcc
OPT = -funroll-loops

# Specify object files
SHA3_OBJS = SHA3.o SWIFFTX.o

# Default target
all: sha3 swifftx

# Compile the main SHA3 executable without Tester.c
sha3: $(SHA3_OBJS)
	${CC} -O3 -DSYS_STDINT ${OPT} -msse2 $(SHA3_OBJS) -o sha3

# Compile the Go program linking with the C object files
swifftx:
	@if [ -f sha3.go ]; then \
		go build -o swifftx sha3.go; \
		if [ $$? -ne 0 ]; then \
			echo "Build failed!"; \
			exit 1; \
		fi; \
	else \
		echo "sha3.go not found!"; \
		exit 1; \
	fi

# Compile C files to object files
%.o: %.c
	${CC} -c $< -o $@

# Debug version without Tester.c
sha3-dbg: $(SHA3_OBJS)
	${CC} -g -lm -DSYS_STDINT $(SHA3_OBJS) -o sha3-dbg

# Clean up
clean: 
	rm -f *.o *.s *~ sha3 sha3-dbg swifftx
