// types.go
package key

// SPHINCS_SK represents a SPHINCS private key structure.
type SPHINCS_SK struct {
	SKseed []byte
	SKprf  []byte
	PKseed []byte
	PKroot []byte
}
