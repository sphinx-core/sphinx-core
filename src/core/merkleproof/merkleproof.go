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

package merkleproof

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
	"golang.org/x/crypto/sha3"
)

// MerkleProof represents the Merkle proof for a particular leaf in the tree
type MerkleProof struct {
	// List of sibling hashes needed to reconstruct the Merkle root
	SiblingHashes [][]byte
	// The index of the leaf in the Merkle tree
	LeafIndex int
}

// CreateMerkleProof constructs a Merkle proof for a given signature and its corresponding Merkle tree
func CreateMerkleProof(sig *sphincs.SPHINCS_SIG, sigParts [][]byte) (*MerkleProof, error) {
	// Build the Merkle tree from the signature parts
	merkleRoot, err := buildMerkleTreeFromSignature(sigParts)
	if err != nil {
		return nil, err
	}

	// Find the index of the leaf node (signature part) in the Merkle tree
	leafIndex := -1
	for i, part := range sigParts {
		// The comparison is done directly with the sigParts as it represents the signature part
		serializedSig, err := sig.SerializeSignature()
		if err != nil {
			return nil, err
		}
		if bytes.Equal(part, serializedSig) { // Use bytes.Equal to compare slices
			leafIndex = i
			break
		}
	}

	if leafIndex == -1 {
		return nil, errors.New("signature part not found in Merkle tree")
	}

	// Generate the Merkle proof by collecting sibling hashes
	proof, err := generateProof(merkleRoot, leafIndex, sigParts)
	if err != nil {
		return nil, err
	}

	return &MerkleProof{
		SiblingHashes: proof,
		LeafIndex:     leafIndex,
	}, nil
}

// generateProof traverses the Merkle tree to generate the proof path
func generateProof(root *hashtree.HashTreeNode, leafIndex int, sigParts [][]byte) ([][]byte, error) {
	// Construct the proof path by traversing the tree and adding sibling hashes
	proof := [][]byte{}

	// Traverse up the tree from the leaf node
	for currentNode := root; currentNode != nil; {
		// If the tree has a way to access the sibling node, update this logic
		siblingNode, err := currentNode.GetSiblingNode(leafIndex)
		if err != nil {
			return nil, err
		}

		// Add the sibling hash to the proof
		if siblingNode != nil {
			proof = append(proof, siblingNode.Hash.Bytes())
		}

		// Move up the tree to the parent node
		currentNode = currentNode.Parent // Ensure that Parent exists or modify accordingly
	}

	if len(proof) == 0 {
		return nil, errors.New("no Merkle proof could be generated")
	}

	return proof, nil
}

// VerifyMerkleProof verifies a Merkle proof by reconstructing the Merkle root and comparing with the provided root
func VerifyMerkleProof(proof *MerkleProof, leafHash []byte, merkleRoot *hashtree.HashTreeNode) bool {
	// Start with the leaf hash and reconstruct the Merkle root using the proof path
	currentHash := leafHash
	for _, siblingHash := range proof.SiblingHashes {
		// Combine the current hash with the sibling hash (could be left or right depending on the tree structure)
		// Here we assume a left-to-right traversal, but this should be adapted based on tree structure
		currentHash = combineHashes(currentHash, siblingHash)
	}

	// Compare the reconstructed hash with the provided Merkle root
	rebuiltRootHash := currentHash
	merkleRootHashBytes := merkleRoot.Hash.Bytes()
	return hex.EncodeToString(rebuiltRootHash) == hex.EncodeToString(merkleRootHashBytes)
}

// combineHashes combines two hashes in a way that is consistent with Merkle tree verification (hash concatenation or other)
func combineHashes(left, right []byte) []byte {
	// Concatenate the left and right hashes (in the case of a binary Merkle tree)
	combined := append(left, right...)

	// Apply SHAKE256 to the combined hashes
	hash := sha3.NewShake256()
	hash.Write(combined)

	// Specify the output length (for example, 32 bytes for the hash output)
	var result [32]byte
	hash.Read(result[:])

	return result[:]
}

// buildMerkleTreeFromSignature builds the Merkle tree from the signature parts and returns the root node
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
