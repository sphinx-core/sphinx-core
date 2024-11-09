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

// KeyManager interface defines methods for sign and verify management and cryptographic operations
type KeyManager interface {
	// SignMessage signs a given message using the secret key, returns the signature and the Merkle tree root node
	SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error)

	// VerifySignature checks if a signature is valid for a given message and public key, using the Merkle tree root node
	VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool

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
// Parameters:
// - params: SPHINCS+ parameters used for the signature verification process.
// - message: The original message that was signed.
// - sig: The signature that needs to be verified.
// - pk: The public key used to verify the signature.
// - merkleRoot: The Merkle tree root used for verifying the integrity of the signature.
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	// Step 1: Perform SPHINCS+ signature verification using the provided message, signature, and public key
	// The Spx_verify function is a cryptographic verification function from SPHINCS+ that checks the validity of the signature.
	// This step uses the SPHINCS+ signature algorithm to confirm if the signature corresponds correctly to the message and public key.
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		// If the verification fails (signature doesn't match), return false.
		return false
	}

	// Step 2: Serialize the signature into a byte slice for further processing
	// The signature is serialized into a byte slice so that it can be manipulated in smaller chunks for Merkle tree reconstruction.
	// If the serialization fails (due to incorrect data format, invalid signature, etc.), return false.
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		// If serialization fails, return false as we cannot proceed with the invalid signature.
		return false
	}

	// Step 3: Split the serialized signature into chunks for Merkle tree reconstruction
	// This step divides the serialized signature (`sigBytes`) into 4 equal parts. However, the total size of the signature might be very large (35,664 bytes in this case).
	// The division into 4 parts is simply to handle it in manageable chunks.
	// The method assumes the signature is chunked evenly, but if the signature size is not a perfect multiple of 4,
	// the last chunk will be smaller and contain the remaining bytes.
	chunkSize := len(sigBytes) / 4 // Determine the chunk size based on the total size of the signature.
	sigParts := make([][]byte, 4)  // Create a slice to store the 4 parts of the signature.

	// Loop to split the signature into 4 chunks.
	for i := 0; i < 4; i++ {
		// Calculate the start and end index for each chunk
		start := i * chunkSize
		end := start + chunkSize

		// For the last chunk, include any remaining bytes that were not equally divided
		if i == 3 {
			end = len(sigBytes) // Ensure the last chunk gets all remaining bytes.
		}

		// Store each chunk into the `sigParts` slice for further use.
		sigParts[i] = sigBytes[start:end]
	}

	// Step 4: Rebuild the Merkle tree from the signature parts
	// After splitting the signature into parts, we rebuild the Merkle tree to check if the root hash matches the provided Merkle root.
	// If rebuilding the Merkle tree fails (due to corrupted data or failure in the tree construction), return false.
	rebuiltRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		// Return false if the Merkle tree could not be reconstructed properly from the signature chunks.
		return false
	}

	// Step 5: Convert the rebuilt Merkle tree root hash to a byte slice
	// The Merkle tree's root hash is extracted and converted to bytes for comparison purposes.
	rebuiltRootHashBytes := rebuiltRoot.Hash.Bytes()

	// Step 6: Compare the rebuilt Merkle root hash with the provided Merkle root hash
	// Convert both hashes (rebuilt and provided) to hex strings and compare them. If they match, the signature is valid.
	merkleRootHashBytes := merkleRoot.Hash.Bytes()

	// Return true if the rebuilt Merkle root hash matches the provided Merkle root hash. This confirms the signature is valid.
	return hex.EncodeToString(rebuiltRootHashBytes) == hex.EncodeToString(merkleRootHashBytes)
}

// Helper functions for serialization and deserialization
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
