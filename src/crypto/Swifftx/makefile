CC = gcc
OPT = -funroll-loops

# Specify object files
SHA3_OBJS = SHA3.o SWIFFTX.o

# Default target
all: swifftx

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

# Clean up
clean: 
	rm -f *.o *.s *~ swifftx
