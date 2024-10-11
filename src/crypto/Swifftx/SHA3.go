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

// Hash function wraps the C Hash function for Go usage
func SwifftxHash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, fmt.Errorf("unsupported hashbitlen: %d", hashbitlen)
	}

	hashval := make([]byte, 65)      // SWIFFTX_OUTPUT_BLOCK_SIZE
	dataLen := uint64(len(data) * 8) // Convert byte length to bit length

	// Convert data to C pointer
	cData := C.CBytes(data)
	defer C.free(cData) // Free allocated memory

	// Convert hashval to C pointer
	cHashval := C.CBytes(hashval)
	defer C.free(cHashval) // Free allocated memory

	// Call the C function
	C.Swifftx(C.int(hashbitlen), (*C.uchar)(cData), C.uint64_t(dataLen), (*C.uchar)(cHashval))

	return hashval, nil
}
