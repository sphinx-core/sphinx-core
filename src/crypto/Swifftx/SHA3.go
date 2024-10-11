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
	"math"
)

const SWIFFTX_OUTPUT_BLOCK_SIZE = 65 // Change this value according to your actual output size

// PrintDigestInHexa formats the hash output in hexadecimal format.
func PrintDigestInHexa(digest []byte, lengthInBytes int, toIdent bool) string {
	result := ""
	spaceCond := 16
	newLineCond := 32

	for i := 0; i < lengthInBytes; i++ {
		if toIdent {
			if i%newLineCond == 0 && i != 0 {
				result += "\n"
			} else if i%spaceCond == 0 {
				result += " "
			}
		}
		result += fmt.Sprintf("%02X", digest[i])
	}
	return result
}

// SwifftxHash wraps the C Hash function for Go usage.
func SwifftxHash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, fmt.Errorf("unsupported hashbitlen: %d", hashbitlen)
	}

	hashval := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE) // Allocate output buffer
	dataLen := uint64(len(data) * 8)                   // Convert byte length to bit length

	// Convert data to C pointer
	cData := C.CBytes(data)
	defer C.free(cData) // Free allocated memory

	// Call the C function
	C.Swifftx(C.int(hashbitlen), (*C.uchar)(cData), C.ulonglong(dataLen), (*C.uchar)(&hashval[0]))

	return hashval, nil
}

// SanityCheck1 tests the hash function with a small input message.
func SanityCheck1() {
	inputMessage := []byte("Hello, world!") // 14 including '\0'
	fmt.Printf("The input message is:\n%s\n\n", inputMessage)

	for _, hashbitlen := range []int{512, 384, 256, 224} {
		resultingDigest, err := SwifftxHash(hashbitlen, inputMessage)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("The resulting digest of size %dbit of the input message is:\n", hashbitlen)
		fmt.Println(PrintDigestInHexa(resultingDigest, hashbitlen/8, true))
		fmt.Println()
	}
}

// PrintTimeAsReadableString formats the time in a human-readable way.
func PrintTimeAsReadableString(value float64) {
	secs := value / 1000.0

	if secs < 60.0 {
		fmt.Printf("%f seconds.\n", secs)
		return
	}

	mins := math.Floor(secs / 60.0)
	secs -= mins * 60

	if mins < 60.0 {
		fmt.Printf("%f minutes and %f seconds.\n", mins, secs)
		return
	}

	hours := math.Floor(mins / 60.0)
	mins -= hours * 60
	fmt.Printf("%f hours, %f minutes and %f seconds.\n", hours, mins, secs)
}

// TimeTest1 measures the time taken for multiple hashing operations.
func TimeTest1() {
	inputMessage := []byte("Hello, world!") // 14 including '\0'
	numOfTrials := uint64(100)              // Reduced for debugging

	startTime := float64(C.clock())

	for i := uint64(0); i < numOfTrials; i++ {
		_, err := SwifftxHash(512, inputMessage)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	endTime := float64(C.clock())
	elapsedTime := endTime - startTime
	fmt.Printf("\nElapsed time was: ")
	PrintTimeAsReadableString(elapsedTime)
}

// Main function to run the tests
func main() {
	SanityCheck1()
	TimeTest1()
}
