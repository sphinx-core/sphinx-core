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

package main

import (
	"fmt"
	"log"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
	sign "github.com/sphinx-core/sphinx-core/src/core/sphincs"
	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	// Initialize parameters for SHAKE256-robust with N = 24
	params := parameters.MakeSphincsPlusSHAKE256192fRobust(false)

	// Open LevelDB
	db, err := leveldb.OpenFile("leaves_db", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	// Initialize the SphincsManager with the LevelDB instance
	manager := sign.NewSphincsManager(db)

	// Generate keys
	sk, pk := manager.GenerateKeys(params)

	// Serialize the secret key to bytes
	skBytes, err := manager.SerializeSK(sk)
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}
	fmt.Printf("Secret Key (SK): %x\n", skBytes)

	// Serialize the public key to bytes
	pkBytes, err := manager.SerializePK(pk)
	if err != nil {
		log.Fatal("Failed to serialize PK:", err)
	}
	fmt.Printf("Public Key (PK): %x\n", pkBytes)

	// Sign a message
	message := []byte("Hello, world!")
	sig, merkleRoot, err := manager.SignMessage(params, message, sk)
	if err != nil {
		log.Fatal("Failed to sign message:", err)
	}

	// Print Merkle Tree root hash
	fmt.Printf("Merkle Tree Root Hash: %x\n", merkleRoot.Hash)

	// Create combined output: data + root hash of signature
	combinedOutput := append(message, merkleRoot.Hash...) // Combining message and Merkle root
	fmt.Printf("Combined Output (Data + Root Hash): %x\n", combinedOutput)

	// Serialize the signature to bytes
	sigBytes, err := manager.SerializeSignature(sig)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}
	fmt.Printf("Signature: %x\n", sigBytes)

	// Save Merkle root hash to a file
	err = hashtree.SaveRootHashToFile(merkleRoot, "merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to save root hash to file:", err)
	}

	// Load Merkle root hash from a file
	loadedHash, err := hashtree.LoadRootHashFromFile("merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to load root hash from file:", err)
	}
	fmt.Printf("Loaded Merkle Tree Root Hash: %x\n", loadedHash)

	// Save leaves to LevelDB
	leaves := [][]byte{sigBytes} // Example usage
	err = hashtree.SaveLeavesToDB(db, leaves)
	if err != nil {
		log.Fatal("Failed to save leaves to DB:", err)
	}

	// Fetch a leaf from LevelDB
	leaf, err := hashtree.FetchLeafFromDB(db, "leaf-0")
	if err != nil {
		log.Fatal("Failed to fetch leaf from DB:", err)
	}
	fmt.Printf("Fetched Leaf: %x\n", leaf)

	// Verify the signature and print the original message
	isValid := manager.VerifySignature(params, message, sig, pk, merkleRoot)
	fmt.Printf("Signature valid: %v\n", isValid)
	if isValid {
		fmt.Printf("Original Message: %s\n", message)
	}
}
