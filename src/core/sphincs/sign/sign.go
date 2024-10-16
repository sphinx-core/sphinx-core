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

package signer

import (
	"encoding/hex"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
	"github.com/syndtr/goleveldb/leveldb"
)

// KeyManager interface defines methods for key management and cryptographic operations
type KeyManager interface {
	SignMessage(params *parameters.Parameters, message []byte, sk *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error)
	VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool
	SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error)
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
		return nil, nil, err
	}

	// Split the serialized signature into parts to build a Merkle tree
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

	// Build a Merkle tree from the signature parts and retrieve the root node
	merkleRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return nil, nil, err
	}

	// Save the leaf nodes (signature parts) into LevelDB in batch mode for performance efficiency
	if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
		return nil, nil, err
	}

	// Prune old leaves from the database to prevent the storage from growing indefinitely
	if err := hashtree.PruneOldLeaves(sm.db, 5); err != nil {
		return nil, nil, err
	}

	// Return the generated signature and the root node of the Merkle tree
	return sig, merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
func (sm *SphincsManager) VerifySignature(params *parameters.Parameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	isValid := sphincs.Spx_verify(params, message, sig, pk)
	if !isValid {
		return false
	}

	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return false
	}

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

	rebuiltRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return false
	}

	return hex.EncodeToString(rebuiltRoot.Hash) == hex.EncodeToString(merkleRoot.Hash)
}

// buildMerkleTreeFromSignature constructs a Merkle tree from signature parts and returns the root node
func buildMerkleTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	tree := hashtree.NewHashTree(sigParts)
	if err := tree.Build(); err != nil {
		return nil, err
	}
	return tree.Root, nil
}
