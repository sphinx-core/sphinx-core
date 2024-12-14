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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package key

import (
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// KeyManager is responsible for managing key generation using SPHINCS+ parameters.
// Fields:
// - Params: Holds the specific SPHINCS+ parameters used for key generation.
type KeyManager struct {
	Params *parameters.Parameters
}

// NewKeyManager initializes a new KeyManager instance with default SPHINCS+ parameters for SHAKE256-192f-robust.
// Returns:
// - KeyManager instance configured with specified SPHINCS+ parameters, or an error if initialization fails.
func NewKeyManager() (*KeyManager, error) {
	// Configure SPHINCS+ parameters (SHAKE256-192f-robust) and return a KeyManager.
	params := parameters.MakeSphincsPlusSHAKE256192fRobust(false)
	if params == nil {
		return nil, errors.New("failed to initialize parameters")
	}
	return &KeyManager{Params: params}, nil
}

// GenerateKey generates a new SPHINCS private and public key pair using SPHINCS+ parameters.
// Returns:
// - SPHINCS_SK: The generated private key structure.
// - sphincs.SPHINCS_PK: The generated public key structure.
// - error: An error if parameters are missing or if key generation fails.
func (km *KeyManager) GenerateKey() (*SPHINCS_SK, *sphincs.SPHINCS_PK, error) {
	// Ensure parameters are initialized.
	if km.Params == nil {
		return nil, nil, errors.New("missing parameters in KeyManager")
	}

	// Generate the SPHINCS+ key pair using the configured parameters.
	sk, pk := sphincs.Spx_keygen(km.Params)
	if sk == nil || pk == nil {
		return nil, nil, errors.New("key generation failed: returned nil for SK or PK")
	}

	// Check if essential fields in keys are non-empty.
	if len(sk.SKseed) == 0 || len(pk.PKseed) == 0 {
		return nil, nil, errors.New("key generation failed: empty key fields")
	}

	// Wrap and return the generated private and public keys.
	return &SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}, pk, nil
}

// SerializeSK serializes the SPHINCS private key to a byte slice.
func (sk *SPHINCS_SK) SerializeSK() ([]byte, error) {
	if sk == nil {
		return nil, errors.New("private key is nil")
	}

	// Combine the SKseed, SKprf, PKseed, and PKroot into a single byte slice.
	data := append(sk.SKseed, sk.SKprf...)
	data = append(data, sk.PKseed...)
	data = append(data, sk.PKroot...)

	return data, nil
}

// SerializeKeyPair serializes a SPHINCS private and public key pair to byte slices.
// Parameters:
// - sk: The SPHINCS private key to serialize.
// - pk: The SPHINCS public key to serialize.
// Returns:
// - Byte slices for the serialized private and public keys.
// - An error if serialization fails or if either key is nil.
// SerializeKeyPair serializes a SPHINCS private and public key pair to byte slices.
func (km *KeyManager) SerializeKeyPair(sk *SPHINCS_SK, pk *sphincs.SPHINCS_PK) ([]byte, []byte, error) {
	if sk == nil || pk == nil {
		return nil, nil, errors.New("private or public key is nil")
	}

	// Serialize the private key.
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return nil, nil, errors.New("failed to serialize private key: " + err.Error())
	}

	// Serialize the public key.
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, nil, errors.New("failed to serialize public key: " + err.Error())
	}

	return skBytes, pkBytes, nil
}

// DeserializeKeyPair reconstructs a SPHINCS private and public key pair from byte slices.
// Parameters:
// - skBytes: Byte slice representing the serialized private key.
// - pkBytes: Byte slice representing the serialized public key.
// Returns:
// - SPHINCS_SK: Deserialized private key structure.
// - sphincs.SPHINCS_PK: Deserialized public key structure.
// - An error if deserialization fails or if parameters are missing.
func (km *KeyManager) DeserializeKeyPair(skBytes, pkBytes []byte) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK, error) {
	if km.Params == nil {
		return nil, nil, errors.New("missing parameters in KeyManager")
	}

	// Deserialize the private key from bytes.
	sk, err := sphincs.DeserializeSK(km.Params, skBytes)
	if err != nil {
		return nil, nil, errors.New("failed to deserialize private key: " + err.Error())
	}

	// Deserialize the public key from bytes.
	pk, err := sphincs.DeserializePK(km.Params, pkBytes)
	if err != nil {
		return nil, nil, errors.New("failed to deserialize public key: " + err.Error())
	}

	return sk, pk, nil
}
