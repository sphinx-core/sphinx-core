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

package keys

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// Initialize parameters for SHAKE256-robust with N = 24
var params = parameters.MakeSphincsPlusSHAKE256192fRobust(false)

// KeyManager interface defines methods for key management
type KeyManager interface {
	GenerateKeys() (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK)
	SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error)
	DeserializeSK(skBytes []byte) (*sphincs.SPHINCS_SK, error)
	SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error)
	DeserializePK(pkBytes []byte) (*sphincs.SPHINCS_PK, error)
}

// SphincsKeyManager implements the KeyManager interface for SPHINCS+ key operations
type SphincsKeyManager struct {
	Params *parameters.Parameters // Store the parameters
}

// NewSphincsKeyManager creates a new instance of SphincsKeyManager with the specified parameters
func NewSphincsKeyManager() *SphincsKeyManager {
	return &SphincsKeyManager{Params: params}
}

// GenerateKeys generates a new pair of secret and public keys using the stored parameters
func (km *SphincsKeyManager) GenerateKeys() (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK) {
	return sphincs.Spx_keygen(km.Params)
}

// SerializeSK serializes the secret key (sk) into a byte slice
func (km *SphincsKeyManager) SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error) {
	return sk.SerializeSK() // Calls the secret key's built-in SerializeSK method
}

// DeserializeSK deserializes a byte slice into a secret key (sk)
func (km *SphincsKeyManager) DeserializeSK(skBytes []byte) (*sphincs.SPHINCS_SK, error) {
	return sphincs.DeserializeSK(km.Params, skBytes) // Use the stored parameters
}

// SerializePK serializes the public key (pk) into a byte slice
func (km *SphincsKeyManager) SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error) {
	return pk.SerializePK() // Calls the public key's built-in SerializePK method
}

// DeserializePK deserializes a byte slice into a public key (pk)
func (km *SphincsKeyManager) DeserializePK(pkBytes []byte) (*sphincs.SPHINCS_PK, error) {
	return sphincs.DeserializePK(km.Params, pkBytes) // Use the stored parameters
}
