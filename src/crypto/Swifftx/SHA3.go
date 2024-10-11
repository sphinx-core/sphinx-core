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

package sha3Swifftx

/*
#cgo CFLAGS: -I.
#include "SHA3.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

void Swifftx(int hashbitlen, unsigned char *data, uint64_t databitlen, unsigned char *hashval) {
    hashState state;
    HashReturn result;

    result = Init(&state, hashbitlen);
    if (result != SUCCESS) {
        return; // Handle error appropriately in production code
    }

    result = Update(&state, data, databitlen);
    if (result != SUCCESS) {
        return; // Handle error appropriately in production code
    }

    result = Final(&state, hashval);
    if (result != SUCCESS) {
        return; // Handle error appropriately in production code
    }
}
*/
import "C"
import (
	"fmt"
)

const SWIFFTX_OUTPUT_BLOCK_SIZE = 65 // Update this if your actual output size is different

// Hash function wraps the C Swifftx function for Go usage
func SwifftxHash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, fmt.Errorf("unsupported hashbitlen: %d", hashbitlen)
	}

	hashval := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE) // Output buffer
	dataLen := uint64(len(data) * 8)                   // Convert byte length to bit length

	// Convert data to C pointer
	cData := C.CBytes(data)
	defer C.free(cData) // Free allocated memory

	// Convert hashval to C pointer
	cHashval := C.CBytes(hashval)
	defer C.free(cHashval) // Free allocated memory

	// Call the C function
	C.Swifftx(C.int(hashbitlen), (*C.uchar)(cData), C.uint64_t(dataLen), (*C.uchar)(cHashval))

	// Copy the result from C to Go's hashval slice
	copy(hashval, (*(*[SWIFFTX_OUTPUT_BLOCK_SIZE]byte)(cHashval))[:])

	return hashval, nil
}

// PrintDigestInHexa prints the digest in hexadecimal format
func PrintDigestInHexa(digest []byte, lengthInBytes int, toIdent bool) string {
	result := make([]byte, (lengthInBytes*2)+4) // Size to accommodate hex representation
	numOfWrittenChars := 0

	for i := 0; i < lengthInBytes; i++ {
		if toIdent {
			if (i%32) == 0 && i != 0 {
				numOfWrittenChars += copy(result[numOfWrittenChars:], "\n")
			} else if (i % 16) == 0 {
				numOfWrittenChars += copy(result[numOfWrittenChars:], " ")
			}
		}
		numOfWrittenChars += copy(result[numOfWrittenChars:], fmt.Sprintf("%02X", digest[i]))
	}

	return string(result[:numOfWrittenChars])
}

// SanityCheck1 tests small input messages for all the digest sizes.
func SanityCheck1() int {
	inputMessage := []byte("Hello, world!") // The input message
	fmt.Printf("The input message is:\n%s\n\n", inputMessage)

	for _, hashSize := range []int{512, 384, 256, 224} {
		resultingDigest := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE) // Buffer to hold the resulting digest
		hash, err := SwifftxHash(hashSize, inputMessage)
		if err != nil {
			fmt.Printf("Failure occurred: %s\n", err)
			return -1
		}
		copy(resultingDigest, hash)
		fmt.Printf("The resulting digest of size %dbit of the input message is:\n", hashSize)
		fmt.Println(PrintDigestInHexa(resultingDigest, SWIFFTX_OUTPUT_BLOCK_SIZE, true))
		fmt.Println()
	}

	return 0
}
