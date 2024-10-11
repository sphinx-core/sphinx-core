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

package sign

import (
	"encoding/hex"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0002 https://github.com/sphinx-core/sips/wiki/SIPS-0002

// KeyManager interface defines methods for key management and cryptographic operations
type KeyManager interface {
	// GenerateKeys generates a new pair of secret and public keys based on the provided parameters
	GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK)

	// SignMessage signs a given message using the secret key, returns the signature and the Merkle tree root node
	SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error)

	// VerifySignature checks if a signature is valid for a given message and public key, using the Merkle tree root node
	VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool

	// SerializeSK converts a secret key to a byte slice
	SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error)

	// DeserializeSK converts a byte slice back into a secret key
	DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error)

	// SerializePK converts a public key to a byte slice
	SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error)

	// DeserializePK converts a byte slice back into a public key
	DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error)

	// SerializeSignature converts a signature to a byte slice
	SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error)

	// DeserializeSignature converts a byte slice back into a signature
	DeserializeSignature(params *parameters.Parameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error)
}

// SphincsManager implements the KeyManager interface for SPHINCS+ operations
type SphincsManager struct {
	db *leveldb.DB // LevelDB instance for storing leaves
}

// NewSphincsManager creates a new instance of SphincsManager with a LevelDB instance
func NewSphincsManager(db *leveldb.DB) *SphincsManager {
	return &SphincsManager{db: db}
}

// GenerateKeys generates a new pair of secret and public keys
func (sm *SphincsManager) GenerateKeys(params *parameters.Parameters) (*sphincs.SPHINCS_SK, *sphincs.SPHINCS_PK) {
	return sphincs.Spx_keygen(params)
}

// SignMessage signs a given message using the secret key
func (sm *SphincsManager) SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*hashtree.HashTreeNode, error) {
	// Generate the SPHINCS+ signature
	sig := sphincs.Spx_sign(params, message, sk)

	// Serialize the generated signature into bytes
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return nil, err
	}

	// Split the serialized signature into 4 equal-sized parts
	chunkSize := len(sigBytes) / 4
	sigParts := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 {
			end = len(sigBytes)
		}
		sigParts[i] = sigBytes[start:end]
	}

	// Build a Merkle tree from the signature parts and get the root node
	merkleRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return nil, err
	}

	// Save the signature parts as leaves in LevelDB
	if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
		return nil, err
	}

	// Prune old leaves if necessary
	if err := hashtree.PruneOldLeaves(sm.db, 5); err != nil {
		return nil, err
	}

	// Return only the Merkle root as the "signature"
	return merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sigParts [][]byte, pk *sphincs.SPHINCS_PK, expectedRootHash []byte) bool {
	// First verify the signature using SPHINCS+
	sig := sphincs.NewSignatureFromParts(sigParts) // Construct signature from parts
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		return false
	}

	// Rebuild the Merkle tree from the signature parts
	rebuiltRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return false
	}

	// Compare the rebuilt Merkle root hash with the expected root hash
	return hex.EncodeToString(rebuiltRoot.Hash) == hex.EncodeToString(expectedRootHash)
}

// Helper functions for key serialization and deserialization
// SerializeSK serializes the secret key (sk) into a byte slice
func (sm *SphincsManager) SerializeSK(sk *sphincs.SPHINCS_SK) ([]byte, error) {
	return sk.SerializeSK() // Calls the secret key's built-in SerializeSK method
}

// DeserializeSK deserializes a byte slice into a secret key (sk) using the provided parameters
func (sm *SphincsManager) DeserializeSK(params *parameters.Parameters, skBytes []byte) (*sphincs.SPHINCS_SK, error) {
	return sphincs.DeserializeSK(params, skBytes) // Calls SPHINCS method to deserialize secret key from bytes
}

// SerializePK serializes the public key (pk) into a byte slice
func (sm *SphincsManager) SerializePK(pk *sphincs.SPHINCS_PK) ([]byte, error) {
	return pk.SerializePK() // Calls the public key's built-in SerializePK method
}

// DeserializePK deserializes a byte slice into a public key (pk) using the provided parameters
func (sm *SphincsManager) DeserializePK(params *parameters.Parameters, pkBytes []byte) (*sphincs.SPHINCS_PK, error) {
	return sphincs.DeserializePK(params, pkBytes) // Calls SPHINCS method to deserialize public key from bytes
}

// SerializeSignature serializes the signature (sig) into a byte slice
func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature() // Calls the signature's built-in SerializeSignature method
}

// DeserializeSignature deserializes a byte slice into a signature (sig) using the provided parameters
func (sm *SphincsManager) DeserializeSignature(params *parameters.Parameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error) {
	return sphincs.DeserializeSignature(params, sigBytes) // Calls SPHINCS method to deserialize signature from bytes
}

// buildMerkleTreeFromSignature constructs a Merkle tree from signature parts and returns the root node
func buildMerkleTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	// Create a new Merkle tree instance with the given signature parts
	tree := hashtree.NewHashTree(sigParts)
	if err := tree.Build(); err != nil {
		// Return an error if the building of the Merkle tree fails
		return nil, err
	}
	// Return the root node of the constructed Merkle tree
	return tree.Root, nil
}
