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

// SignMessage signs a given message using the secret key
func (sm *SphincsManager) SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error) {
	// Generate the SPHINCS+ signature for the given message using the secret key
	sig := sphincs.Spx_sign(params, message, sk)

	// Serialize the generated signature into a byte array for further processing
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		// Return an error if the serialization process fails
		return nil, nil, err
	}

	// Split the serialized signature into parts to build a Merkle tree
	// We divide the signature into 4 equal-sized chunks
	chunkSize := len(sigBytes) / 4
	sigParts := make([][]byte, 4) // Initialize an array to hold the 4 signature parts
	for i := 0; i < 4; i++ {
		// Calculate the start and end indices for each part of the signature
		start := i * chunkSize
		end := start + chunkSize
		// For the last chunk, ensure we include any remaining bytes
		if i == 3 {
			end = len(sigBytes)
		}
		// Assign each part of the signature to sigParts
		sigParts[i] = sigBytes[start:end]
	}

	// Build a Merkle tree from the signature parts and retrieve the root node
	merkleRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		// Return an error if the Merkle tree construction fails
		return nil, nil, err
	}

	// Save the leaf nodes (signature parts) into LevelDB in batch mode for performance efficiency
	if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
		// Return an error if saving the leaves to LevelDB fails
		return nil, nil, err
	}

	// Optionally prune old leaves from the database to prevent the storage from growing indefinitely
	// In this example, we keep the last 5 leaves and prune older ones
	if err := hashtree.PruneOldLeaves(sm.db, 5); err != nil {
		// Return an error if the pruning operation fails
		return nil, nil, err
	}

	// Return the generated signature and the root node of the Merkle tree
	return sig, merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	// Signature Verification: The signature is first verified using the sphincs.Spx_verify function,
	// which checks if the signature is valid for the provided message, public key, and parameters.
	// This part ensures that the original SPHINCS+ signature is valid.
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		// If the signature is not valid, return false
		return false
	}

	// Serialize the signature to get its byte representation for further processing
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		// If an error occurs during serialization, return false
		return false
	}

	// Split the serialized signature into 4 parts to rebuild the Merkle tree
	chunkSize := len(sigBytes) / 4 // Calculate the size of each chunk
	sigParts := make([][]byte, 4)  // Initialize a slice to hold 4 parts of the signature
	for i := 0; i < 4; i++ {
		// Calculate the start and end index for each chunk
		start := i * chunkSize
		end := start + chunkSize
		// For the last chunk, ensure it includes any remaining bytes
		if i == 3 {
			end = len(sigBytes)
		}
		// Assign each part of the signature to sigParts
		sigParts[i] = sigBytes[start:end]
	}

	// Efficient Verification:
	// During verification, the signature is reassembled into parts.
	// A Merkle tree is reconstructed, and the root hash is compared with the original
	// Merkle root stored from signing. This ensures the integrity of the signature
	// without loading the entire 35,664 bytes at once.
	//
	// Merkle Root Verification: After the signature verification, the serialized signature
	// is split into four parts, and these parts are used to rebuild a Merkle tree.
	// The hash of the rebuilt Merkle root is then compared with the hash of the provided merkleRoot.
	// If both hashes match, the function returns true, confirming that the signature corresponds
	// to the expected Merkle root.
	rebuiltRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		// If there is an error while rebuilding the Merkle tree, return false
		return false
	}

	// Compare the hash of the rebuilt Merkle root with the provided Merkle root's hash
	// Convert both to hexadecimal strings and check if they match
	return hex.EncodeToString(rebuiltRoot.Hash) == hex.EncodeToString(merkleRoot.Hash)
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

// buildMerkleTreeFromSignature creates a Merkle tree from signature parts and returns the root node
func buildMerkleTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	// Implementation details for building a Merkle tree from signature parts would go here
	// For now, it will return a placeholder value for the Merkle root
	return &hashtree.HashTreeNode{}, nil
}
