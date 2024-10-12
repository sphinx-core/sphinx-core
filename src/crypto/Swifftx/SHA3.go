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

package swifftx

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: ./SWIFFTX ./SHA3
#include "SWIFFTX.h"
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
	"unsafe"
)

const SWIFFTX_OUTPUT_BLOCK_SIZE = 65 // Change this value according to your actual output size

// SwifftxHash wraps the C Swifftx function for Go usage
func SwifftxHash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, fmt.Errorf("unsupported hashbitlen: %d", hashbitlen)
	}

	hashval := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE) // Allocate memory for the hash output
	dataLen := uint64(len(data) * 8)                   // Convert byte length to bit length

	// Convert data to C pointer
	cData := (*C.uchar)(C.CBytes(data))
	defer C.free(unsafe.Pointer(cData)) // Free allocated memory

	// Convert hashval to C pointer
	cHashval := (*C.uchar)(C.CBytes(hashval))
	defer C.free(unsafe.Pointer(cHashval)) // Free allocated memory

	// Call the C function
	C.Swifftx(C.int(hashbitlen), cData, C.uint64_t(dataLen), cHashval)

	// Manually create the Go slice from the C buffer
	hashOutput := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE)
	copy(hashOutput, (*[SWIFFTX_OUTPUT_BLOCK_SIZE]byte)(unsafe.Pointer(cHashval))[:])

	return hashOutput, nil
}
