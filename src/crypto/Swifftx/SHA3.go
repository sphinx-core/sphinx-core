package sha3

/*
#cgo CFLAGS: -I. // This should point to the directory where SHA3.h is located.
#include "SHA3.h"
#include <stdlib.h>

void GoSHA3Hash(int hashbitlen, unsigned char *data, uint64_t databitlen, unsigned char *hashval) {
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
func Hash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, fmt.Errorf("unsupported hashbitlen: %d", hashbitlen)
	}

	hashval := make([]byte, 65)      // SWIFFTX_OUTPUT_BLOCK_SIZE
	dataLen := uint64(len(data) * 8) // Convert byte length to bit length

	// Call the C function
	C.GoSHA3Hash(C.int(hashbitlen), (*C.uchar)(C.CBytes(data)), C.uint64_t(dataLen), (*C.uchar)(C.CBytes(hashval)))

	return hashval, nil
}
