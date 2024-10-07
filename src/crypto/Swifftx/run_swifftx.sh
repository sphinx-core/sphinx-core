#!/bin/bash

# Set the DYLD_LIBRARY_PATH to include the path to the library
export DYLD_LIBRARY_PATH=/Users/kusuma/Desktop/bc-go-v1/crypto/Swifftx:$DYLD_LIBRARY_PATH

# Change permissions for the libSWIFFTX.dylib file
chmod +r /Users/kusuma/Desktop/bc-go-v1/crypto/Swifftx/libSWIFFTX.dylib

# Run the Go program
go run swifftx.go
