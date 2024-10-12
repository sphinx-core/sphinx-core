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
#include "SWIFFTX.h" // Ensure the case matches exactly
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Wrapper function to call ComputeSingleSWIFFTX in Go
void SwifftxHashWrapper(unsigned char input[SWIFFTX_INPUT_BLOCK_SIZE], unsigned char output[SWIFFTX_OUTPUT_BLOCK_SIZE], bool doSmooth) {
    ComputeSingleSWIFFTX(input, output, doSmooth);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Define constants that align with the C header values
const (
	SWIFFTX_INPUT_BLOCK_SIZE  = 256 // 256 bytes (2048 bits)
	SWIFFTX_OUTPUT_BLOCK_SIZE = 64  // 64 bytes (512 bits)
)

// SwifftxHash performs the SWIFFTX hash operation on input data
func SwifftxHash(input []byte, doSmooth bool) ([]byte, error) {
	if len(input) != SWIFFTX_INPUT_BLOCK_SIZE {
		return nil, errors.New("input must be exactly 256 bytes")
	}

	// Prepare output buffer
	output := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE)

	// Convert Go slice to C array (for input and output)
	cInput := (*C.uchar)(C.CBytes(input))
	defer C.free(unsafe.Pointer(cInput)) // Free the C memory when done

	cOutput := (*C.uchar)(C.CBytes(output))
	defer C.free(unsafe.Pointer(cOutput))

	// Call the wrapper function to invoke SWIFFTX hashing
	C.SwifftxHashWrapper(cInput, cOutput, C.bool(doSmooth))

	// Copy result from C output array to Go slice
	hashOutput := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE)
	copy(hashOutput, C.GoBytes(unsafe.Pointer(cOutput), C.int(SWIFFTX_OUTPUT_BLOCK_SIZE)))

	return hashOutput, nil
}
