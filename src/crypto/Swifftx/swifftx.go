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
#cgo LDFLAGS: -L. -lSHA3
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  // Include for sprintf
#include "SHA3.h"

void HashInput(const char *input, int length, char *output) {
    BitSequence resultingDigest[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    HashReturn exitCode;

    exitCode = Hash(512, (const BitSequence *)input, length * 8, resultingDigest);  // 512-bit output

    if (exitCode == SUCCESS) {
        for (int i = 0; i < 64; i++) { // 64 bytes for 512 bits
            sprintf(output + (i * 2), "%02X", resultingDigest[i]); // Convert to hex
        }
    }
}
*/
import "C"
import (
	"unsafe"
)

func SWIFFTXHash(input string) (string, error) {
	length := len(input)
	output := make([]byte, 128) // 64 bytes = 512 bits, each byte represented by 2 hex chars

	cInput := C.CString(input)
	defer C.free(unsafe.Pointer(cInput))

	C.HashInput(cInput, C.int(length), (*C.char)(unsafe.Pointer(&output[0])))

	return string(output), nil
}
