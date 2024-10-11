// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

/*
#cgo CFLAGS: -I.           // Include the current directory for headers
#cgo LDFLAGS: -L. -lSHA3   // Link against the SHA3 library
#include "SHA3.h"           // Include the SHA3 header
#include <stdlib.h>         // For C standard library functions
#include <string.h>         // For string functions
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

const (
	SWIFFTX_OUTPUT_BLOCK_SIZE = 64 // Adjust according to your needs
)

// Hash is a wrapper function that calls the C Hash function.
func Hash(outputSize int, inputMessage []byte) ([]byte, error) {
	var resultingDigest [SWIFFTX_OUTPUT_BLOCK_SIZE]C.BitSequence
	inputLength := C.DataLength(len(inputMessage) * 8) // Length in bits
	message := C.CBytes(inputMessage)                  // Convert Go slice to C array
	defer C.free(message)                              // Ensure memory is freed

	// Call the C Hash function
	exitCode := C.Hash(C.int(outputSize), (*C.BitSequence)(message), inputLength, &resultingDigest[0])
	if exitCode != C.SUCCESS {
		return nil, fmt.Errorf("hashing failed with error code: %d", exitCode)
	}

	// Convert the C array to a Go slice
	digest := C.GoBytes(unsafe.Pointer(&resultingDigest[0]), C.int(outputSize/8))
	return digest, nil
}

// Test function to demonstrate hashing
func swifftx() {
	inputMessage := []byte("Hello, world!")  // Message to hash
	outputSizes := []int{512, 384, 256, 224} // Different hash output sizes

	for _, size := range outputSizes {
		digest, err := Hash(size, inputMessage) // Call the hash function
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Printf("Hash output for size %d: %x\n", size, digest) // Print the hash output
	}
}

// Main function
func main() {
	// Set the DYLD_LIBRARY_PATH to ensure the dynamic library is found
	libraryPath := "/Users/kusuma/Desktop/sphinx-core/src/crypto/Swifftx" // Path to the library
	if err := os.Setenv("DYLD_LIBRARY_PATH", libraryPath); err != nil {
		fmt.Printf("Error setting DYLD_LIBRARY_PATH: %v\n", err)
		return
	}

	// Call the test function to run the hash demonstration
	swifftx()
}
